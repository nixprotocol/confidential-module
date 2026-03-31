package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgRegisterKey{}, "confidential/MsgRegisterKey", nil)
	cdc.RegisterConcrete(&MsgShield{}, "confidential/MsgShield", nil)
	cdc.RegisterConcrete(&MsgConfidentialSend{}, "confidential/MsgConfidentialSend", nil)
	cdc.RegisterConcrete(&MsgApplyPending{}, "confidential/MsgApplyPending", nil)
	cdc.RegisterConcrete(&MsgUnshield{}, "confidential/MsgUnshield", nil)
	cdc.RegisterConcrete(&MsgSetAuditorKey{}, "confidential/MsgSetAuditorKey", nil)
}

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRegisterKey{},
		&MsgShield{},
		&MsgConfidentialSend{},
		&MsgApplyPending{},
		&MsgUnshield{},
		&MsgSetAuditorKey{},
	)
}
