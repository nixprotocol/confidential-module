package keeper

import (
	"context"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	sdk "github.com/cosmos/cosmos-sdk/types"

	elgamal "github.com/nixprotocol/elgamal-bn254"

	"github.com/nixprotocol/confidential-module/types"
)

// ConfidentialSend handles the MsgConfidentialSend message: verifies equality
// and aggregate range proofs, then homomorphically updates sender's available
// balance and receiver's pending balance.
func (k msgServer) ConfidentialSend(goCtx context.Context, msg *types.MsgConfidentialSend) (*types.MsgConfidentialSendResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Resolve addresses.
	senderAddr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}
	senderBytes := senderAddr.Bytes()

	receiverAddr, err := sdk.AccAddressFromBech32(msg.Receiver)
	if err != nil {
		return nil, types.ErrAccountNotRegistered.Wrap("invalid receiver address")
	}
	receiverBytes := receiverAddr.Bytes()

	// 2. Check both keys registered.
	if !k.HasRegisteredKey(ctx, senderBytes) {
		return nil, types.ErrAccountNotRegistered.Wrap("sender has no registered key")
	}
	if !k.HasRegisteredKey(ctx, receiverBytes) {
		return nil, types.ErrAccountNotRegistered.Wrap("receiver has no registered key")
	}

	// 3. Load and validate params.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	if len(params.AuditorPubKey) == 0 {
		return nil, types.ErrInvalidAuditorKey.Wrap("auditor key not set")
	}
	if !isDenomEnabled(params, msg.Denom) {
		return nil, types.ErrDenomNotEnabled.Wrapf("denom %s is not enabled", msg.Denom)
	}

	// 4. Check receiver key counter matches (protect against key rotation race).
	receiverCounter, err := k.GetKeyCounter(ctx, receiverBytes)
	if err != nil {
		return nil, err
	}
	if msg.ReceiverKeyCounter != receiverCounter {
		return nil, types.ErrKeyCounterMismatch.Wrap("receiver key has been rotated since transaction was created")
	}

	// 5. Get public keys for sender, receiver, and auditor.
	senderPkBytes, err := k.GetAccountPubkey(ctx, senderBytes)
	if err != nil {
		return nil, err
	}
	senderPk, err := unmarshalPublicKey(senderPkBytes)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap(err.Error())
	}

	receiverPkBytes, err := k.GetAccountPubkey(ctx, receiverBytes)
	if err != nil {
		return nil, err
	}
	receiverPk, err := unmarshalPublicKey(receiverPkBytes)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap(err.Error())
	}

	auditorPk, err := unmarshalPublicKey(params.AuditorPubKey)
	if err != nil {
		return nil, types.ErrInvalidAuditorKey.Wrap(err.Error())
	}

	// 6. Unmarshal all three ciphertexts.
	senderCt, err := unmarshalCiphertext(msg.SenderUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("sender_update: " + err.Error())
	}
	receiverCt, err := unmarshalCiphertext(msg.ReceiverUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("receiver_update: " + err.Error())
	}
	auditorCt, err := unmarshalCiphertext(msg.AuditorUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("auditor_update: " + err.Error())
	}

	// 7. Verify equality proof: all three ciphertexts encrypt the same amount.
	if err := k.verifyEquality(ctx, msg.EqualityProof, &senderPk, &receiverPk, &auditorPk, senderCt, receiverCt, auditorCt, msg.Sender, msg.Receiver, msg.Denom); err != nil {
		return nil, err
	}

	// 8. Prepare commitments for aggregate range proof.
	// The range proof verifies two statements:
	//   (a) transfer amount >= 0
	//   (b) sender's new available balance >= 0
	//
	// The C2 component of an ElGamal ciphertext Enc(v, pk, r) = (r*G, v*G + r*pk)
	// is a Pedersen commitment with blinding base H = pk.
	// For the sender: H = senderPk.
	//
	// Commitment 1: senderCt.C2 = transferAmount*G + r_sender*senderPk
	// Commitment 2: (availableBalance - senderCt).C2 = newBalance*G + r_new*senderPk
	availBytes, err := k.GetAvailableBalance(ctx, senderBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	availCt, err := unmarshalCiphertext(availBytes)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("stored available balance: " + err.Error())
	}

	// Compute new balance ciphertext: available - senderUpdate
	newBalanceCt := elgamal.Sub(availCt, senderCt)

	// The commitments for the range proof are the C2 components.
	commitments := []bn254.G1Affine{senderCt.C2, newBalanceCt.C2}

	// 9. Verify aggregate range proof.
	if err := k.verifyAggregateRange(ctx, msg.RangeProof, commitments, &senderPk, params.MaxTransferBits, msg.Sender, msg.Receiver, msg.Denom); err != nil {
		return nil, err
	}

	// 10. Update sender's available balance: available -= senderUpdate.
	newAvail, err := subCiphertexts(availBytes, msg.SenderUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}
	if err := k.SetAvailableBalance(ctx, senderBytes, msg.Denom, newAvail); err != nil {
		return nil, err
	}

	// 11. Update receiver's pending balance: pending += receiverUpdate.
	pendBytes, err := k.GetPendingBalance(ctx, receiverBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	newPend, err := addCiphertexts(pendBytes, msg.ReceiverUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}
	if err := k.SetPendingBalance(ctx, receiverBytes, msg.Denom, newPend); err != nil {
		return nil, err
	}

	// 12. Clear the receiver's pending-is-zero flag (they now have incoming funds).
	if err := k.SetPendingIsZero(ctx, receiverBytes, msg.Denom, false); err != nil {
		return nil, err
	}

	// 13. Emit event with the auditor ciphertext for audit trail.
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeConfidentialSend,
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyReceiver, msg.Receiver),
		sdk.NewAttribute(types.AttributeKeyDenom, msg.Denom),
		sdk.NewAttribute(types.AttributeKeyAuditorCiphertext, fmt.Sprintf("%x", msg.AuditorUpdate)),
	))

	return &types.MsgConfidentialSendResponse{}, nil
}
