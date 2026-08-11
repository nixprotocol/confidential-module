package keeper

import (
	"context"
	"errors"
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
		return nil, types.ErrKeyNotRegistered.Wrap("invalid receiver address")
	}
	if senderAddr.Equals(receiverAddr) {
		return nil, types.ErrInvalidAmount.Wrap("sender and receiver must be different")
	}
	receiverBytes := receiverAddr.Bytes()

	// 2. Get registered pubkeys for sender and receiver (single store read each).
	senderPk, err := k.getRegisteredPubkey(ctx, senderBytes)
	if err != nil {
		if errors.Is(err, types.ErrKeyNotRegistered) {
			return nil, types.ErrKeyNotRegistered.Wrap("sender has no registered key")
		}
		return nil, err
	}
	receiverPk, err := k.getRegisteredPubkey(ctx, receiverBytes)
	if err != nil {
		if errors.Is(err, types.ErrKeyNotRegistered) {
			return nil, types.ErrKeyNotRegistered.Wrap("receiver has no registered key")
		}
		return nil, err
	}

	// 3. Load and validate params.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	if len(params.AuditorPubKey) == 0 {
		return nil, types.ErrAuditorKeyNotSet.Wrap("auditor key not set")
	}

	// 4. Unmarshal auditor pubkey.
	auditorPk, err := unmarshalPublicKey(params.AuditorPubKey)
	if err != nil {
		return nil, types.ErrAuditorKeyNotSet.Wrap(err.Error())
	}

	// 5. Unmarshal all three ciphertexts.
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

	// 6. Verify equality proof: all three ciphertexts encrypt the same amount.
	if err := k.verifyEquality(ctx, msg.EqualityProof, &senderPk, &receiverPk, &auditorPk, senderCt, receiverCt, auditorCt, msg.Sender, msg.Receiver, msg.Denom); err != nil {
		return nil, err
	}

	// 7. Prepare commitments for the aggregate range proof.
	// The range proof verifies two statements:
	//   (a) transfer amount is in range
	//   (b) sender's new available balance is in range (i.e. did not go negative)
	//
	// These are NOT taken over the ciphertexts. An ElGamal ciphertext
	// Enc(v, pk, r) = (r*G, v*G + r*pk) has a C2 that looks like a Pedersen
	// commitment with blinding base pk — but pk = sk*G and the sender knows sk,
	// so C2 = (v + r*sk)*G can be re-opened to any value at all. A range proof
	// over C2 with Hbase = senderPk constrains nothing for the sender, who is
	// exactly the party submitting it.
	//
	// Instead the sender supplies real Pedersen commitments blinded by a
	// nothing-up-my-sleeve base H, and a commitment-equality proof per
	// commitment tying it to the corresponding ciphertext. The range proof then
	// runs over the binding commitments.
	transferCommitment, err := unmarshalCommitment(msg.TransferCommitment)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("transfer_commitment: " + err.Error())
	}
	remainingCommitment, err := unmarshalCommitment(msg.RemainingCommitment)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("remaining_commitment: " + err.Error())
	}

	availBytes, err := k.GetAvailableBalance(ctx, senderBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	availCt, err := unmarshalOrZero(availBytes)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("stored available balance: " + err.Error())
	}

	// Compute new balance ciphertext: available - senderUpdate
	newBalanceCt := elgamal.Sub(availCt, senderCt)

	// 8. Tie each commitment to the ciphertext it claims to describe.
	if err := k.verifyCommitmentEquality(ctx, msg.TransferCommitmentProof, &senderPk, senderCt,
		&transferCommitment, commitmentRoleTransfer, msg.Sender, msg.Receiver, msg.Denom); err != nil {
		return nil, err
	}
	if err := k.verifyCommitmentEquality(ctx, msg.RemainingCommitmentProof, &senderPk, &newBalanceCt,
		&remainingCommitment, commitmentRoleRemaining, msg.Sender, msg.Receiver, msg.Denom); err != nil {
		return nil, err
	}

	// 9. Verify aggregate range proof over the binding commitments.
	commitments := []bn254.G1Affine{transferCommitment, remainingCommitment}
	if err := k.verifyAggregateRange(ctx, msg.RangeProof, commitments, RangeProofBlindingBase(), int(params.MaxTransferBits), msg.Sender, msg.Receiver, msg.Denom); err != nil {
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
	eventAttrs := []sdk.Attribute{
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyReceiver, msg.Receiver),
		sdk.NewAttribute(types.AttributeKeyDenom, msg.Denom),
		sdk.NewAttribute(types.AttributeKeyAuditorCiphertext, fmt.Sprintf("%x", msg.AuditorUpdate)),
	}
	if len(msg.EncryptedMemo) > 0 {
		eventAttrs = append(eventAttrs, sdk.NewAttribute(types.AttributeKeyEncryptedMemo, fmt.Sprintf("%x", msg.EncryptedMemo)))
	}
	if len(msg.AuditorMemo) > 0 {
		eventAttrs = append(eventAttrs, sdk.NewAttribute(types.AttributeKeyAuditorMemo, fmt.Sprintf("%x", msg.AuditorMemo)))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeConfidentialSend,
		eventAttrs...,
	))

	return &types.MsgConfidentialSendResponse{}, nil
}
