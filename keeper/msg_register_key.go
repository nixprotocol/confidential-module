package keeper

import (
	"context"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// RegisterKey handles the MsgRegisterKey message: validates the public key,
// stores it with counter 0, and initializes zero-encrypted balances for all
// enabled denominations.
func (k msgServer) RegisterKey(goCtx context.Context, msg *types.MsgRegisterKey) (*types.MsgRegisterKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate the public key (on-curve, not identity).
	pk, err := unmarshalPublicKey(msg.Pubkey)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap(err.Error())
	}

	// 2. Resolve sender address to bytes.
	senderAddr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}
	addrBytes := senderAddr.Bytes()

	// 3. Check not already registered.
	if k.HasRegisteredKey(ctx, addrBytes) {
		return nil, types.ErrAccountAlreadyRegistered.Wrap("key already registered for this account")
	}

	// 4. Counter must be 0 for initial registration.
	if msg.Counter != 0 {
		return nil, types.ErrKeyCounterMismatch.Wrap("initial counter must be 0")
	}

	// 5. Store pubkey and counter.
	if err := k.SetAccountPubkey(ctx, addrBytes, msg.Pubkey); err != nil {
		return nil, err
	}
	if err := k.SetKeyCounter(ctx, addrBytes, 0); err != nil {
		return nil, err
	}

	// 6. Initialize zero-encrypted balances for all enabled denoms.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	for _, denom := range params.EnabledDenoms {
		// Encrypt 0 with deterministic randomness (consensus-safe).
		availBytes, err := deterministicZeroEncrypt(ctx, &pk, addrBytes, denom, "register/available")
		if err != nil {
			return nil, types.ErrInvalidCiphertext.Wrapf("failed to encrypt zero for available balance: %v", err)
		}
		if err := k.SetAvailableBalance(ctx, addrBytes, denom, availBytes); err != nil {
			return nil, err
		}

		pendBytes, err := deterministicZeroEncrypt(ctx, &pk, addrBytes, denom, "register/pending")
		if err != nil {
			return nil, types.ErrInvalidCiphertext.Wrapf("failed to encrypt zero for pending balance: %v", err)
		}
		if err := k.SetPendingBalance(ctx, addrBytes, denom, pendBytes); err != nil {
			return nil, err
		}

		// Mark pending as zero since we just initialized it.
		if err := k.SetPendingIsZero(ctx, addrBytes, denom, true); err != nil {
			return nil, err
		}
	}

	// 7. Emit event.
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeRegisterKey,
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
	))

	return &types.MsgRegisterKeyResponse{}, nil
}
