package types

import "fmt"

// DefaultParams returns sensible default parameters.
func DefaultParams() Params {
	return Params{
		AuditorPubKey:         nil,
		PrevAuditorPubKey:     nil,
		AuditorRotationHeight: 0,
		AuditorKeyGracePeriod: 100,
		EnabledDenoms:         []string{},
		MaxTransferBits:       64,
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
	if p.MaxTransferBits <= 0 || p.MaxTransferBits > 64 {
		return fmt.Errorf("max_transfer_bits must be in (0, 64], got %d", p.MaxTransferBits)
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
