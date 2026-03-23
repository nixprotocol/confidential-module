package keeper

import (
	"github.com/nixprotocol/confidential-module/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface.
func NewMsgServerImpl(keeper Keeper) types.MsgServer { return &msgServer{Keeper: keeper} }

var _ types.MsgServer = &msgServer{}

// isDenomEnabled checks whether a denomination is in the enabled list.
func isDenomEnabled(params types.Params, denom string) bool {
	for _, d := range params.EnabledDenoms {
		if d == denom {
			return true
		}
	}
	return false
}
