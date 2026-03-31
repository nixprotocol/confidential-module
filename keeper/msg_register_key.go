package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// RegisterKey handles the MsgRegisterKey message: validates the public key
// and stores it for the account.
func (k msgServer) RegisterKey(goCtx context.Context, msg *types.MsgRegisterKey) (*types.MsgRegisterKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate the public key (on-curve, not identity).
	_, err := unmarshalPublicKey(msg.Pubkey)
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
		return nil, types.ErrKeyAlreadyRegistered.Wrap("key already registered for this account")
	}

	// 4. Store pubkey.
	if err := k.SetAccountPubkey(ctx, addrBytes, msg.Pubkey); err != nil {
		return nil, err
	}

	// 5. Emit event.
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeRegisterKey,
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyPubkey, fmt.Sprintf("%x", msg.Pubkey)),
	))

	return &types.MsgRegisterKeyResponse{}, nil
}
