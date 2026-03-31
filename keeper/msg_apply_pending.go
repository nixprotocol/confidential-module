package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// ApplyPending handles the MsgApplyPending message: verifies the ApplyPending
// proof (that the user correctly decrypted pending and re-encrypted to a new
// available-balance ciphertext), updates available balance, and resets pending
// to a fresh encryption of zero.
func (k msgServer) ApplyPending(goCtx context.Context, msg *types.MsgApplyPending) (*types.MsgApplyPendingResponse, error) {
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

	// 3. Get current pending balance.
	// 4a. Check PendingIsZero flag — reject if nothing to apply.
	isZero, err := k.GetPendingIsZero(ctx, addrBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	if isZero {
		return nil, types.ErrNothingPending.Wrap("pending balance is zero; nothing to apply")
	}

	pendBytes, err := k.GetPendingBalance(ctx, addrBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	if pendBytes == nil {
		return nil, types.ErrNothingPending.Wrap("no pending balance for this denom")
	}
	pendCt, err := unmarshalCiphertext(pendBytes)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("stored pending balance: " + err.Error())
	}

	// 6. Unmarshal the new available update ciphertext.
	newCt, err := unmarshalCiphertext(msg.NewAvailableUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap("new_available_update: " + err.Error())
	}

	// 7. Verify ApplyPending proof.
	// The proof demonstrates that the user:
	//   - knows the secret key sk
	//   - correctly decrypted the pending ciphertext
	//   - re-encrypted the sum (available + pending plaintext) under the same pk
	//     with new randomness
	if err := k.verifyApplyPending(ctx, msg.Proof, &pk, pendCt, newCt, msg.Sender, msg.Denom); err != nil {
		return nil, err
	}

	// 8. Get current available balance and compute the sum.
	availBytes, err := k.GetAvailableBalance(ctx, addrBytes, msg.Denom)
	if err != nil {
		return nil, err
	}

	// The new available balance is: old_available + new_available_update
	// The user provides new_available_update which encodes the pending amount
	// re-encrypted with new randomness.
	newAvail, err := addCiphertexts(availBytes, msg.NewAvailableUpdate)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}
	if err := k.SetAvailableBalance(ctx, addrBytes, msg.Denom, newAvail); err != nil {
		return nil, err
	}

	// 9. Reset pending balance to Enc(0) with deterministic non-zero randomness.
	blockHeight := uint64(ctx.BlockHeight())
	zeroBytes, err := deterministicZeroEncrypt(&pk, addrBytes, msg.Denom, blockHeight)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrapf("failed to encrypt zero for pending reset: %v", err)
	}
	if err := k.SetPendingBalance(ctx, addrBytes, msg.Denom, zeroBytes); err != nil {
		return nil, err
	}

	// 10. Set pending-is-zero flag to true.
	if err := k.SetPendingIsZero(ctx, addrBytes, msg.Denom, true); err != nil {
		return nil, err
	}

	// 11. Emit event.
	eventAttrs := []sdk.Attribute{
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyDenom, msg.Denom),
	}
	if len(msg.EncryptedMemo) > 0 {
		eventAttrs = append(eventAttrs, sdk.NewAttribute(types.AttributeKeyEncryptedMemo, fmt.Sprintf("%x", msg.EncryptedMemo)))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(types.EventTypeApplyPending, eventAttrs...))

	return &types.MsgApplyPendingResponse{}, nil
}
