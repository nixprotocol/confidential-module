package types

import "fmt"

// DefaultParams returns sensible default parameters.
func DefaultParams() Params {
	return Params{
		AuditorPubKey:   nil,
		MaxTransferBits: 64,
	}
}

// Validate checks parameter constraints.
func (p Params) Validate() error {
	if len(p.AuditorPubKey) != 0 && len(p.AuditorPubKey) != 64 {
		return fmt.Errorf("auditor public key must be 64 bytes, got %d", len(p.AuditorPubKey))
	}
	if p.MaxTransferBits <= 0 || p.MaxTransferBits > 64 {
		return fmt.Errorf("max_transfer_bits must be in (0, 64], got %d", p.MaxTransferBits)
	}
	return nil
}
