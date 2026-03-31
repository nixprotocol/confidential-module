package types

// Event type constants for x/confidential module.
const (
	EventTypeRegisterKey      = "register_key"
	EventTypeShield           = "shield"
	EventTypeConfidentialSend = "confidential_send"
	EventTypeApplyPending     = "apply_pending"
	EventTypeUnshield         = "unshield"
	EventTypeSetAuditorKey    = "set_auditor_key"
)

// Attribute key constants shared across events.
const (
	AttributeKeySender            = "sender"
	AttributeKeyReceiver          = "receiver"
	AttributeKeyDenom             = "denom"
	AttributeKeyAmount            = "amount"
	AttributeKeyPubkey            = "pubkey"
	AttributeKeyAuditorPubkey     = "auditor_pubkey"
	AttributeKeyAuditorCiphertext = "auditor_ciphertext"
	AttributeKeyEncryptedMemo     = "encrypted_memo"
	AttributeKeyAuditorMemo       = "auditor_memo"
)
