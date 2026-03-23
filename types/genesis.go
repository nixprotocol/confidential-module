package types

import "fmt"

// BalanceEntry stores a ciphertext balance for a specific denomination.
type BalanceEntry struct {
	Denom      string `json:"denom"`
	Ciphertext []byte `json:"ciphertext"` // 128 bytes
}

// AccountState stores the full confidential state for a single account.
type AccountState struct {
	Address           string         `json:"address"`
	Pubkey            []byte         `json:"pubkey"`             // 64 bytes
	KeyCounter        uint32         `json:"key_counter"`
	AvailableBalances []BalanceEntry `json:"available_balances"`
	PendingBalances   []BalanceEntry `json:"pending_balances"`
	RotationHeight    uint64         `json:"rotation_height"`
}

// GenesisState defines the confidential module genesis state.
type GenesisState struct {
	Params   Params         `json:"params"`
	Accounts []AccountState `json:"accounts"`
}

// DefaultGenesisState returns the default genesis with empty accounts and default params.
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params:   DefaultParams(),
		Accounts: []AccountState{},
	}
}

// Validate performs genesis state validation.
func (gs GenesisState) Validate() error {
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

		for j, bal := range acct.AvailableBalances {
			if bal.Denom == "" {
				return fmt.Errorf("account %d (%s): available balance %d: denom cannot be empty", i, acct.Address, j)
			}
			if len(bal.Ciphertext) != 128 {
				return fmt.Errorf("account %d (%s): available balance %d: ciphertext must be 128 bytes, got %d", i, acct.Address, j, len(bal.Ciphertext))
			}
		}

		for j, bal := range acct.PendingBalances {
			if bal.Denom == "" {
				return fmt.Errorf("account %d (%s): pending balance %d: denom cannot be empty", i, acct.Address, j)
			}
			if len(bal.Ciphertext) != 128 {
				return fmt.Errorf("account %d (%s): pending balance %d: ciphertext must be 128 bytes, got %d", i, acct.Address, j, len(bal.Ciphertext))
			}
		}
	}

	return nil
}
