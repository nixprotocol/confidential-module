package types

import "fmt"

// Params defines the module parameters.
type Params struct {
	// AuditorPubKey is the current auditor ElGamal public key (64 bytes, uncompressed G1).
	AuditorPubKey []byte `json:"auditor_pub_key"`
	// PrevAuditorPubKey is the previous auditor key kept during grace period.
	PrevAuditorPubKey []byte `json:"prev_auditor_pub_key,omitempty"`
	// AuditorRotationHeight is the block height at which the auditor key was last rotated.
	AuditorRotationHeight uint64 `json:"auditor_rotation_height"`
	// AuditorKeyGracePeriod is the number of blocks the previous auditor key remains valid.
	AuditorKeyGracePeriod uint64 `json:"auditor_key_grace_period"`
	// EnabledDenoms is the list of token denominations that can be shielded.
	EnabledDenoms []string `json:"enabled_denoms"`
	// MaxTransferBits is the bit width for range proofs. Must be <= 40 to match BSGS decryption limit.
	MaxTransferBits int `json:"max_transfer_bits"`
	// RotationCooldown is the minimum number of blocks between key rotations for an account.
	RotationCooldown uint64 `json:"rotation_cooldown"`
	// MaxMemoSize is the maximum plaintext memo size in bytes.
	MaxMemoSize int `json:"max_memo_size"`
}

// DefaultParams returns sensible default parameters.
func DefaultParams() Params {
	return Params{
		AuditorPubKey:         nil,
		PrevAuditorPubKey:     nil,
		AuditorRotationHeight: 0,
		AuditorKeyGracePeriod: 100,
		EnabledDenoms:         []string{},
		MaxTransferBits:       40,
		RotationCooldown:      100,
		MaxMemoSize:           1024,
	}
}

// Validate checks parameter constraints.
func (p Params) Validate() error {
	if len(p.AuditorPubKey) != 0 && len(p.AuditorPubKey) != 64 {
		return fmt.Errorf("auditor public key must be 64 bytes, got %d", len(p.AuditorPubKey))
	}
	if len(p.PrevAuditorPubKey) != 0 && len(p.PrevAuditorPubKey) != 64 {
		return fmt.Errorf("previous auditor public key must be 64 bytes, got %d", len(p.PrevAuditorPubKey))
	}
	if p.MaxTransferBits <= 0 || p.MaxTransferBits > 40 {
		return fmt.Errorf("max_transfer_bits must be in (0, 40], got %d (limited by BSGS decryption table)", p.MaxTransferBits)
	}
	for _, denom := range p.EnabledDenoms {
		if denom == "" {
			return fmt.Errorf("enabled denom cannot be empty")
		}
	}
	if p.MaxMemoSize < 0 || p.MaxMemoSize > 4096 {
		return fmt.Errorf("max_memo_size must be in [0, 4096], got %d", p.MaxMemoSize)
	}
	return nil
}
