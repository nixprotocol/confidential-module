package types

import "context"

// MsgServer defines the server API for the confidential module message handlers.
type MsgServer interface {
	RegisterKey(context.Context, *MsgRegisterKey) (*MsgRegisterKeyResponse, error)
	Shield(context.Context, *MsgShield) (*MsgShieldResponse, error)
	ConfidentialSend(context.Context, *MsgConfidentialSend) (*MsgConfidentialSendResponse, error)
	ApplyPending(context.Context, *MsgApplyPending) (*MsgApplyPendingResponse, error)
	Unshield(context.Context, *MsgUnshield) (*MsgUnshieldResponse, error)
	SetAuditorKey(context.Context, *MsgSetAuditorKey) (*MsgSetAuditorKeyResponse, error)
	RotateKey(context.Context, *MsgRotateKey) (*MsgRotateKeyResponse, error)
}

// Response types for each message handler.

type MsgRegisterKeyResponse struct{}
type MsgShieldResponse struct{}
type MsgConfidentialSendResponse struct{}
type MsgApplyPendingResponse struct{}
type MsgUnshieldResponse struct{}
type MsgSetAuditorKeyResponse struct{}
type MsgRotateKeyResponse struct{}
