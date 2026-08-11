package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	sdk "github.com/cosmos/cosmos-sdk/types"

	elgamal "github.com/nixprotocol/elgamal-bn254"

	"github.com/nixprotocol/confidential-module/types"
)

// Unshield handles the MsgUnshield message: verifies the DLEQ proof that the
// ciphertext encrypts the claimed amount, verifies a range proof that the
// remaining balance is non-negative, subtracts the ciphertext from available
// balance, and credits x/bank.
//
// Note: Unshield does NOT require an auditor key. The unshield amount is public
// (emitted in the event and visible in x/bank), so the auditor gains no
// additional information. This allows users to withdraw funds even before
// governance has configured an auditor. ConfidentialSend is the only operation
// that requires the auditor key (for the auditor ciphertext).
func (k msgServer) Unshield(goCtx context.Context, msg *types.MsgUnshield) (*types.MsgUnshieldResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Resolve sender address.
	senderAddr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}
	addrBytes := senderAddr.Bytes()

	// 2. Get sender's registered pubkey (single store read + unmarshal).
	pk, err := k.getRegisteredPubkey(ctx, addrBytes)
	if err != nil {
		return nil, err
	}

	// 3. Load params.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	if len(params.AuditorPubKey) == 0 {
		ctx.Logger().Warn("confidential: unshield proceeding without auditor key configured")
	}

	// 4. Parse amount.
	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok || !amt.IsPositive() {
		return nil, types.ErrInvalidAmount.Wrap("amount must be a positive integer")
	}

	// 5. Check amount fits in MaxTransferBits.
	if amt.BigInt().BitLen() > int(params.MaxTransferBits) {
		return nil, types.ErrInvalidAmount.Wrapf("amount exceeds %d-bit limit", params.MaxTransferBits)
	}

	// 6. Unmarshal the submitted ciphertext.
	ct, err := unmarshalCiphertext(msg.Ciphertext)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}

	// 7. Defensive guard: ensure amount fits in uint64.
	if !amt.IsUint64() {
		return nil, types.ErrInvalidAmount.Wrap("amount does not fit in uint64")
	}

	// 8. Verify DLEQ proof that the ciphertext encrypts the claimed amount.
	if err := k.verifyDLEQ(ctx, msg.DecryptionProof, &pk, ct, amt.Uint64(), msg.Sender, msg.Denom); err != nil {
		return nil, err
	}

	// 9. Compute the remaining balance ciphertext.
	availBytes, err := k.GetAvailableBalance(ctx, addrBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	availCt, err := unmarshalOrZero(availBytes)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("stored available balance: " + err.Error())
	}
	remainingCt := elgamal.Sub(availCt, ct)

	// 10. The range proof runs over a Pedersen commitment blinded by a
	// nothing-up-my-sleeve base, not over remainingCt.C2. C2's blinding base is
	// the sender's own public key, whose discrete log the sender knows, so C2
	// can be re-opened to any value and a range proof over it would prove
	// nothing. The commitment-equality proof ties the commitment back to
	// remainingCt.
	remainingCommitment, err := unmarshalCommitment(msg.RemainingCommitment)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("remaining_commitment: " + err.Error())
	}
	if err := k.verifyCommitmentEquality(ctx, msg.RemainingCommitmentProof, &pk, &remainingCt,
		&remainingCommitment, commitmentRoleRemaining, msg.Sender, "", msg.Denom); err != nil {
		return nil, err
	}

	// 11. Verify range proof: remaining balance is in range (did not go negative).
	commitments := []bn254.G1Affine{remainingCommitment}
	if err := k.verifyAggregateRange(ctx, msg.RangeProof, commitments, RangeProofBlindingBase(), int(params.MaxTransferBits), msg.Sender, "", msg.Denom); err != nil {
		return nil, err
	}

	// 12. Update available balance: available -= ciphertext.
	newAvail, err := subCiphertexts(availBytes, msg.Ciphertext)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}
	if err := k.SetAvailableBalance(ctx, addrBytes, msg.Denom, newAvail); err != nil {
		return nil, err
	}

	// 13. Credit plaintext tokens back to x/bank.
	coin := sdk.NewCoin(msg.Denom, amt)
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleAccountName, senderAddr, sdk.NewCoins(coin)); err != nil {
		return nil, types.ErrInsufficientBalance.Wrap(err.Error())
	}

	// 14. Emit event (plaintext amount is public for unshield operations).
	eventAttrs := []sdk.Attribute{
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyDenom, msg.Denom),
		sdk.NewAttribute(types.AttributeKeyAmount, msg.Amount),
	}
	if len(msg.EncryptedMemo) > 0 {
		eventAttrs = append(eventAttrs, sdk.NewAttribute(types.AttributeKeyEncryptedMemo, fmt.Sprintf("%x", msg.EncryptedMemo)))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeUnshield,
		eventAttrs...,
	))

	return &types.MsgUnshieldResponse{}, nil
}
