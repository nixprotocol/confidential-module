package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/core/address"
	"cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"
	proto "github.com/cosmos/gogoproto/proto"

	"github.com/nixprotocol/confidential-module/types"
)

// Keeper maintains the confidential module state.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	addressCodec address.Codec
	bankKeeper   types.BankKeeper
	authority    []byte
}

// NewKeeper creates a new confidential module keeper.
// Panics if the authority address cannot be encoded — this indicates a fatal
// app misconfiguration that must be fixed before the chain can start.
func NewKeeper(
	storeService store.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authority []byte,
	bankKeeper types.BankKeeper,
) Keeper {
	if _, err := addressCodec.BytesToString(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", err))
	}
	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		addressCodec: addressCodec,
		bankKeeper:   bankKeeper,
		authority:    authority,
	}
}

// GetAuthority returns the module authority address as bytes.
func (k Keeper) GetAuthority() []byte {
	return k.authority
}

// GetAddressCodec returns the address codec.
func (k Keeper) GetAddressCodec() address.Codec {
	return k.addressCodec
}

// ---------- Params ----------

// SetParams stores the module parameters.
func (k Keeper) SetParams(ctx context.Context, params types.Params) error {
	if err := params.Validate(); err != nil {
		return err
	}
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := proto.Marshal(&params)
	if err != nil {
		return err
	}
	return kvStore.Set(types.ParamsKeyBytes(), bz)
}

// GetParams returns the module parameters.
func (k Keeper) GetParams(ctx context.Context) (types.Params, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.ParamsKeyBytes())
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var params types.Params
	if err := proto.Unmarshal(bz, &params); err != nil {
		return types.Params{}, err
	}
	return params, nil
}

// ---------- Account Pubkey ----------

// SetAccountPubkey stores the ElGamal public key for an account.
func (k Keeper) SetAccountPubkey(ctx context.Context, addr []byte, pubkey []byte) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.AccountPubkeyKey(addr), pubkey)
}

// GetAccountPubkey retrieves the ElGamal public key for an account.
// Returns nil, nil if the key does not exist.
func (k Keeper) GetAccountPubkey(ctx context.Context, addr []byte) ([]byte, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Get(types.AccountPubkeyKey(addr))
}

// HasRegisteredKey returns true if the account has a registered ElGamal public key.
// Store errors are propagated to the caller rather than silently treated as
// "not registered" — the latter could allow key re-registration on store corruption.
func (k Keeper) HasRegisteredKey(ctx context.Context, addr []byte) (bool, error) {
	pk, err := k.GetAccountPubkey(ctx, addr)
	if err != nil {
		return false, err
	}
	return pk != nil, nil
}

// ---------- Available Balance ----------

// SetAvailableBalance stores the available (main) encrypted balance for an
// account and denomination.
func (k Keeper) SetAvailableBalance(ctx context.Context, addr []byte, denom string, ciphertext []byte) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.AvailableBalanceKey(addr, denom), ciphertext)
}

// GetAvailableBalance retrieves the available encrypted balance.
// Returns nil, nil if not found.
func (k Keeper) GetAvailableBalance(ctx context.Context, addr []byte, denom string) ([]byte, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Get(types.AvailableBalanceKey(addr, denom))
}

// ---------- Pending Balance ----------

// SetPendingBalance stores the pending encrypted balance for an account and denomination.
func (k Keeper) SetPendingBalance(ctx context.Context, addr []byte, denom string, ciphertext []byte) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.PendingBalanceKey(addr, denom), ciphertext)
}

// GetPendingBalance retrieves the pending encrypted balance.
// Returns nil, nil if not found.
func (k Keeper) GetPendingBalance(ctx context.Context, addr []byte, denom string) ([]byte, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Get(types.PendingBalanceKey(addr, denom))
}

// ---------- Pending Is Zero Flag ----------

// SetPendingIsZero stores the pending-is-zero flag for an account and denomination.
func (k Keeper) SetPendingIsZero(ctx context.Context, addr []byte, denom string, isZero bool) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	val := []byte{0}
	if isZero {
		val = []byte{1}
	}
	return kvStore.Set(types.PendingIsZeroKey(addr, denom), val)
}

// GetPendingIsZero returns true if the pending balance is known to be zero
// (i.e., was reset by ApplyPending and no new sends have arrived).
func (k Keeper) GetPendingIsZero(ctx context.Context, addr []byte, denom string) (bool, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.PendingIsZeroKey(addr, denom))
	if err != nil {
		return false, err
	}
	if bz == nil {
		return false, nil
	}
	return len(bz) == 1 && bz[0] == 1, nil
}
