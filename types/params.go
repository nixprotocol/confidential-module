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
	// MaxTransferBits is the bit width for range proofs (e.g. 64).
	MaxTransferBits int `json:"max_transfer_bits"`
	// RotationCooldown is the minimum number of blocks between key rotations for an account.
	RotationCooldown uint64 `json:"rotation_cooldown"`
}

// DefaultParams returns sensible default parameters.
func DefaultParams() Params {
	return Params{
		AuditorPubKey:         nil,
		PrevAuditorPubKey:     nil,
		AuditorRotationHeight: 0,
		AuditorKeyGracePeriod: 1000,
		EnabledDenoms:         []string{},
		MaxTransferBits:       64,
		RotationCooldown:      100,
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
	if p.MaxTransferBits <= 0 || p.MaxTransferBits > 64 {
		return fmt.Errorf("max_transfer_bits must be in (0, 64], got %d", p.MaxTransferBits)
	}
	for _, denom := range p.EnabledDenoms {
		if denom == "" {
			return fmt.Errorf("enabled denom cannot be empty")
		}
	}
	return nil
}
