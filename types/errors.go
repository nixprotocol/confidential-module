package types

import "cosmossdk.io/errors"

// Error codes aligned with spec Section 5.7.
//
// Reserved codes (removed, do not reuse):
//
//	1005 — was ErrDenomNotEnabled (denom whitelist removed)
//	1009 — was ErrRangeProofFailed (merged into ErrInvalidProof to prevent oracle attacks)
//	1010 — was ErrEqualityProofFailed (same reason)
//	1014 — was ErrInvalidCounter (key rotation removed)
//	1015 — was ErrReceiverKeyRotated (key rotation removed)
//	1016 — was ErrRotationCooldown (key rotation removed)
//	1018 — was ErrPendingNotZero (key rotation removed)
var (
	ErrInvalidPubkey        = errors.Register(ModuleName, 1001, "invalid public key")
	ErrKeyAlreadyRegistered = errors.Register(ModuleName, 1002, "key already registered")
	ErrKeyNotRegistered     = errors.Register(ModuleName, 1003, "key not registered")
	ErrAuditorKeyNotSet     = errors.Register(ModuleName, 1004, "auditor key not set")
	ErrInsufficientFunds    = errors.Register(ModuleName, 1006, "insufficient funds")
	ErrInsufficientBalance  = errors.Register(ModuleName, 1007, "insufficient balance")
	ErrInvalidProof         = errors.Register(ModuleName, 1008, "proof verification failed")
	ErrAmountOverflow       = errors.Register(ModuleName, 1011, "amount overflow")
	ErrNothingPending       = errors.Register(ModuleName, 1012, "nothing pending")
	ErrUnauthorized         = errors.Register(ModuleName, 1013, "unauthorized")
	ErrInvalidCiphertext    = errors.Register(ModuleName, 1017, "invalid ciphertext")
	ErrInvalidParams        = errors.Register(ModuleName, 1019, "invalid module parameters")
	ErrInvalidMemo          = errors.Register(ModuleName, 1020, "invalid memo")
	ErrInvalidAmount        = errors.Register(ModuleName, 1021, "invalid amount")
)
