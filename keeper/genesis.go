package keeper

import (
	"context"
	"encoding/binary"

	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// InitGenesis restores all confidential module state from the genesis export.
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	// 1. Set params.
	if gs.Params != nil {
		if err := k.SetParams(ctx, *gs.Params); err != nil {
			return err
		}
	} else {
		if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
			return err
		}
	}

	// 2. Restore each account.
	for _, acct := range gs.Accounts {
		addr, err := sdk.AccAddressFromBech32(acct.Address)
		if err != nil {
			return err
		}
		addrBytes := addr.Bytes()

		// Store pubkey.
		if err := k.SetAccountPubkey(ctx, addrBytes, acct.Pubkey); err != nil {
			return err
		}

		// Store key counter.
		if err := k.SetKeyCounter(ctx, addrBytes, acct.KeyCounter); err != nil {
			return err
		}

		// Store rotation height.
		if acct.RotationHeight > 0 {
			if err := k.SetRotationHeight(ctx, addrBytes, acct.RotationHeight); err != nil {
				return err
			}
		}

		// Store available balances.
		for _, bal := range acct.AvailableBalances {
			if err := k.SetAvailableBalance(ctx, addrBytes, bal.Denom, bal.Ciphertext); err != nil {
				return err
			}
		}

		// Store pending balances.
		for _, bal := range acct.PendingBalances {
			if err := k.SetPendingBalance(ctx, addrBytes, bal.Denom, bal.Ciphertext); err != nil {
				return err
			}
		}

		// Store PendingIsZero flags.
		for _, piz := range acct.PendingIsZero {
			if err := k.SetPendingIsZero(ctx, addrBytes, piz.Denom, piz.IsZero); err != nil {
				return err
			}
		}
	}

	return nil
}

// ExportGenesis exports the full confidential module state for genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	gs := &types.GenesisState{
		Params: &params,
	}

	store := k.storeService.OpenKVStore(ctx)

	// Iterate all accounts by scanning the AccountPubkeyPrefix.
	pkPrefix := types.AccountPubkeyPrefix()
	pkItems, err := iteratePrefix(store, pkPrefix)
	if err != nil {
		return nil, err
	}

	pkPrefixLen := len(pkPrefix)

	for _, kv := range pkItems {
		// Extract the address bytes from the key.
		addrBytes := kv.key[pkPrefixLen:]

		// Convert address bytes to bech32 string.
		addr := sdk.AccAddress(addrBytes)
		addrStr, err := k.addressCodec.BytesToString(addr)
		if err != nil {
			return nil, err
		}

		acct := &types.AccountState{
			Address: addrStr,
			Pubkey:  kv.value,
		}

		// Get key counter.
		counter, err := k.GetKeyCounter(ctx, addrBytes)
		if err != nil {
			return nil, err
		}
		acct.KeyCounter = counter

		// Get rotation height.
		rotHeight, err := k.GetRotationHeight(ctx, addrBytes)
		if err != nil {
			return nil, err
		}
		acct.RotationHeight = rotHeight

		// Collect available balances by iterating AvailableBalancePrefix + addr + "/".
		availPrefix := types.AvailableBalanceKey(addrBytes, "")
		availItems, err := iteratePrefix(store, availPrefix)
		if err != nil {
			return nil, err
		}
		availPrefixLen := len(availPrefix)
		for _, ab := range availItems {
			denom := string(ab.key[availPrefixLen:])
			acct.AvailableBalances = append(acct.AvailableBalances, &types.BalanceEntry{
				Denom:      denom,
				Ciphertext: ab.value,
			})
		}

		// Collect pending balances by iterating PendingBalancePrefix + addr + "/".
		pendPrefix := types.PendingBalanceKey(addrBytes, "")
		pendItems, err := iteratePrefix(store, pendPrefix)
		if err != nil {
			return nil, err
		}
		pendPrefixLen := len(pendPrefix)
		for _, pb := range pendItems {
			denom := string(pb.key[pendPrefixLen:])
			acct.PendingBalances = append(acct.PendingBalances, &types.BalanceEntry{
				Denom:      denom,
				Ciphertext: pb.value,
			})
		}

		// Collect PendingIsZero flags by iterating PendingIsZeroPrefix + addr + "/".
		pizPrefix := types.PendingIsZeroKey(addrBytes, "")
		pizItems, err := iteratePrefix(store, pizPrefix)
		if err != nil {
			return nil, err
		}
		pizPrefixLen := len(pizPrefix)
		for _, pz := range pizItems {
			denom := string(pz.key[pizPrefixLen:])
			isZero := len(pz.value) > 0 && pz.value[0] == 1
			acct.PendingIsZero = append(acct.PendingIsZero, &types.PendingIsZeroEntry{
				Denom:  denom,
				IsZero: isZero,
			})
		}

		gs.Accounts = append(gs.Accounts, acct)
	}

	return gs, nil
}

type kvPair struct {
	key   []byte
	value []byte
}

// iteratePrefix collects all key-value pairs under a given prefix.
func iteratePrefix(store interface {
	Iterator(start, end []byte) (storetypes.Iterator, error)
}, prefix []byte) ([]kvPair, error) {
	end := storetypes.PrefixEndBytes(prefix)
	iter, err := store.Iterator(prefix, end)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var pairs []kvPair
	for ; iter.Valid(); iter.Next() {
		k := make([]byte, len(iter.Key()))
		copy(k, iter.Key())
		v := make([]byte, len(iter.Value()))
		copy(v, iter.Value())
		pairs = append(pairs, kvPair{key: k, value: v})
	}
	return pairs, nil
}

// Ensure binary import is used.
var _ = binary.BigEndian
