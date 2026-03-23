package types

import "cosmossdk.io/errors"

var (
	ErrAccountNotRegistered   = errors.Register(ModuleName, 1001, "account not registered")
	ErrAccountAlreadyRegistered = errors.Register(ModuleName, 1002, "account already registered")
	ErrInvalidPubkey          = errors.Register(ModuleName, 1003, "invalid public key")
	ErrInvalidCiphertext      = errors.Register(ModuleName, 1004, "invalid ciphertext")
	ErrDenomNotEnabled        = errors.Register(ModuleName, 1005, "denomination not enabled")
	ErrInvalidAmount          = errors.Register(ModuleName, 1006, "invalid amount")
	ErrInsufficientBalance    = errors.Register(ModuleName, 1007, "insufficient balance")
	ErrInvalidProof           = errors.Register(ModuleName, 1008, "proof verification failed")
	ErrRangeProofFailed       = errors.Register(ModuleName, 1009, "proof verification failed")
	ErrEqualityProofFailed    = errors.Register(ModuleName, 1010, "proof verification failed")
	ErrPendingBalanceEmpty    = errors.Register(ModuleName, 1011, "pending balance is empty")
	ErrInvalidAuditorKey      = errors.Register(ModuleName, 1012, "invalid auditor public key")
	ErrKeyCounterMismatch     = errors.Register(ModuleName, 1013, "key counter mismatch")
	ErrRotationCooldown       = errors.Register(ModuleName, 1014, "rotation cooldown not elapsed")
	ErrUnauthorized           = errors.Register(ModuleName, 1015, "unauthorized")
	ErrInvalidParams          = errors.Register(ModuleName, 1016, "invalid module parameters")
)
