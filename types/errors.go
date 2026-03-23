package types

import "cosmossdk.io/errors"

// Error codes aligned with spec Section 5.7.
// ErrRangeProofFailed and ErrEqualityProofFailed are intentionally removed —
// all proof failures use ErrInvalidProof to prevent oracle attacks.
var (
	ErrInvalidPubkey        = errors.Register(ModuleName, 1001, "invalid public key")
	ErrKeyAlreadyRegistered = errors.Register(ModuleName, 1002, "key already registered")
	ErrKeyNotRegistered     = errors.Register(ModuleName, 1003, "key not registered")
	ErrAuditorKeyNotSet     = errors.Register(ModuleName, 1004, "auditor key not set")
	ErrDenomNotEnabled      = errors.Register(ModuleName, 1005, "denomination not enabled")
	ErrInsufficientFunds    = errors.Register(ModuleName, 1006, "insufficient funds")
	ErrInsufficientBalance  = errors.Register(ModuleName, 1007, "insufficient balance")
	ErrInvalidProof         = errors.Register(ModuleName, 1008, "proof verification failed")
	ErrAmountOverflow       = errors.Register(ModuleName, 1011, "amount overflow")
	ErrNothingPending       = errors.Register(ModuleName, 1012, "nothing pending")
	ErrUnauthorized         = errors.Register(ModuleName, 1013, "unauthorized")
	ErrInvalidCounter       = errors.Register(ModuleName, 1014, "invalid counter")
	ErrReceiverKeyRotated   = errors.Register(ModuleName, 1015, "receiver key rotated")
	ErrRotationCooldown     = errors.Register(ModuleName, 1016, "rotation cooldown not elapsed")

	// Additional errors not in the core spec table but required by the module.
	ErrInvalidCiphertext = errors.Register(ModuleName, 1017, "invalid ciphertext")
	ErrPendingNotZero    = errors.Register(ModuleName, 1018, "pending balance is not zero; call ApplyPending first")
	ErrInvalidParams     = errors.Register(ModuleName, 1019, "invalid module parameters")
	ErrInvalidMemo       = errors.Register(ModuleName, 1020, "invalid memo")
	ErrInvalidAmount     = errors.Register(ModuleName, 1021, "invalid amount")
)
