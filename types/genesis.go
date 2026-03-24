package types

import (
	"fmt"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// DefaultGenesisState returns the default genesis with empty accounts and default params.
func DefaultGenesisState() *GenesisState {
	params := DefaultParams()
	return &GenesisState{
		Params:   &params,
		Accounts: []*AccountState{},
	}
}

// Validate performs genesis state validation.
func (gs GenesisState) Validate() error {
	if gs.Params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}

	// If denominations are enabled, auditor key is required.
	if len(gs.Params.EnabledDenoms) > 0 && len(gs.Params.AuditorPubKey) == 0 {
		return fmt.Errorf("auditor public key is required when denominations are enabled")
	}

	seen := make(map[string]bool)
	for i, acct := range gs.Accounts {
		if acct.Address == "" {
			return fmt.Errorf("account %d: address cannot be empty", i)
		}
		if seen[acct.Address] {
			return fmt.Errorf("account %d: duplicate address %s", i, acct.Address)
		}
		seen[acct.Address] = true

		if len(acct.Pubkey) != 64 {
			return fmt.Errorf("account %d (%s): pubkey must be 64 bytes, got %d", i, acct.Address, len(acct.Pubkey))
		}

		// Validate pubkey is a valid BN254 G1 point (on-curve, not identity).
		if _, err := elgamal.UnmarshalPublicKey(acct.Pubkey); err != nil {
			return fmt.Errorf("account %s: invalid pubkey: %w", acct.Address, err)
		}

		for j, bal := range acct.AvailableBalances {
			if bal.Denom == "" {
				return fmt.Errorf("account %d (%s): available balance %d: denom cannot be empty", i, acct.Address, j)
			}
			if len(bal.Ciphertext) != 128 {
				return fmt.Errorf("account %d (%s): available balance %d: ciphertext must be 128 bytes, got %d", i, acct.Address, j, len(bal.Ciphertext))
			}
			// Validate ciphertext points are on curve.
			var ct elgamal.Ciphertext
			if err := ct.Unmarshal(bal.Ciphertext); err != nil {
				return fmt.Errorf("account %s denom %s: invalid available ciphertext: %w", acct.Address, bal.Denom, err)
			}
		}

		for j, bal := range acct.PendingBalances {
			if bal.Denom == "" {
				return fmt.Errorf("account %d (%s): pending balance %d: denom cannot be empty", i, acct.Address, j)
			}
			if len(bal.Ciphertext) != 128 {
				return fmt.Errorf("account %d (%s): pending balance %d: ciphertext must be 128 bytes, got %d", i, acct.Address, j, len(bal.Ciphertext))
			}
			// Validate ciphertext points are on curve.
			var ct elgamal.Ciphertext
			if err := ct.Unmarshal(bal.Ciphertext); err != nil {
				return fmt.Errorf("account %s denom %s: invalid pending ciphertext: %w", acct.Address, bal.Denom, err)
			}
		}
	}

	return nil
}
