package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// Shield handles the MsgShield message: debits plaintext tokens from x/bank,
// verifies a DLEQ proof that the ciphertext encrypts the claimed amount, and
// homomorphically adds the ciphertext to the sender's available balance.
func (k msgServer) Shield(goCtx context.Context, msg *types.MsgShield) (*types.MsgShieldResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Resolve sender address.
	senderAddr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}
	addrBytes := senderAddr.Bytes()

	// 2. Check key registered.
	if !k.HasRegisteredKey(ctx, addrBytes) {
		return nil, types.ErrAccountNotRegistered.Wrap("sender has no registered key")
	}

	// 3. Load and validate params.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// 4. Check auditor key is set.
	if len(params.AuditorPubKey) == 0 {
		return nil, types.ErrInvalidAuditorKey.Wrap("auditor key not set")
	}

	// 5. Check denom enabled.
	if !isDenomEnabled(params, msg.Denom) {
		return nil, types.ErrDenomNotEnabled.Wrapf("denom %s is not enabled", msg.Denom)
	}

	// 6. Parse amount.
	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok || !amt.IsPositive() {
		return nil, types.ErrInvalidAmount.Wrap("amount must be a positive integer")
	}

	// 7. Check amount fits in MaxTransferBits.
	if amt.BigInt().BitLen() > params.MaxTransferBits {
		return nil, types.ErrInvalidAmount.Wrapf("amount exceeds %d-bit limit", params.MaxTransferBits)
	}

	// 8. Get sender's pubkey.
	pkBytes, err := k.GetAccountPubkey(ctx, addrBytes)
	if err != nil {
		return nil, err
	}
	pk, err := unmarshalPublicKey(pkBytes)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap(err.Error())
	}

	// 9. Unmarshal the submitted ciphertext.
	ct, err := unmarshalCiphertext(msg.Ciphertext)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}

	// 10. Verify DLEQ proof that the ciphertext encrypts the claimed amount.
	if err := k.verifyDLEQ(ctx, msg.Proof, &pk, ct, amt.Uint64(), msg.Sender, msg.Denom); err != nil {
		return nil, err
	}

	// 11. Debit plaintext tokens from x/bank.
	coin := sdk.NewCoin(msg.Denom, amt)
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, senderAddr, types.ModuleAccountName, sdk.NewCoins(coin)); err != nil {
		return nil, types.ErrInsufficientBalance.Wrap(err.Error())
	}

	// 12. Homomorphically add ciphertext to available balance.
	availBytes, err := k.GetAvailableBalance(ctx, addrBytes, msg.Denom)
	if err != nil {
		return nil, err
	}
	newAvail, err := addCiphertexts(availBytes, msg.Ciphertext)
	if err != nil {
		return nil, types.ErrInvalidCiphertext.Wrap(err.Error())
	}
	if err := k.SetAvailableBalance(ctx, addrBytes, msg.Denom, newAvail); err != nil {
		return nil, err
	}

	// 13. Emit event (plaintext amount is public for shield operations).
	eventAttrs := []sdk.Attribute{
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyDenom, msg.Denom),
		sdk.NewAttribute(types.AttributeKeyAmount, msg.Amount),
	}
	if len(msg.EncryptedMemo) > 0 {
		eventAttrs = append(eventAttrs, sdk.NewAttribute(types.AttributeKeyEncryptedMemo, fmt.Sprintf("%x", msg.EncryptedMemo)))
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeShield,
		eventAttrs...,
	))

	return &types.MsgShieldResponse{}, nil
}
