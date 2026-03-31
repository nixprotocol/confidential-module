package keeper

import (
	"bytes"
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// SetAuditorKey handles the MsgSetAuditorKey governance message: validates the
// authority, validates the new auditor public key, and stores it in params.
func (k msgServer) SetAuditorKey(goCtx context.Context, msg *types.MsgSetAuditorKey) (*types.MsgSetAuditorKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Check authority = governance.
	authorityAddr, err := k.addressCodec.StringToBytes(msg.Authority)
	if err != nil {
		return nil, fmt.Errorf("invalid authority address: %w", err)
	}
	if !bytes.Equal(authorityAddr, k.GetAuthority()) {
		expectedStr, _ := k.addressCodec.BytesToString(k.GetAuthority())
		return nil, types.ErrUnauthorized.Wrapf("expected %s, got %s", expectedStr, msg.Authority)
	}

	// 2. Validate the new auditor public key (on-curve, not identity).
	if _, err := unmarshalPublicKey(msg.Pubkey); err != nil {
		return nil, types.ErrAuditorKeyNotSet.Wrap(err.Error())
	}

	// 3. Load current params and set the new auditor key.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	params.AuditorPubKey = msg.Pubkey

	// 4. Store updated params.
	if err := k.SetParams(ctx, params); err != nil {
		return nil, err
	}

	// 5. Emit event.
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeSetAuditorKey,
		sdk.NewAttribute(types.AttributeKeyAuditorPubkey, fmt.Sprintf("%x", msg.Pubkey)),
	))

	return &types.MsgSetAuditorKeyResponse{}, nil
}
