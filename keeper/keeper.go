package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/address"
	"cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

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
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := json.Marshal(params)
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
	if err := json.Unmarshal(bz, &params); err != nil {
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
func (k Keeper) HasRegisteredKey(ctx context.Context, addr []byte) bool {
	pk, err := k.GetAccountPubkey(ctx, addr)
	return err == nil && pk != nil
}

// ---------- Key Counter ----------

// SetKeyCounter stores the key counter for an account.
func (k Keeper) SetKeyCounter(ctx context.Context, addr []byte, counter uint32) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], counter)
	return kvStore.Set(types.AccountKeyCounterKey(addr), buf[:])
}

// GetKeyCounter retrieves the key counter for an account.
// Returns 0, nil if not found.
func (k Keeper) GetKeyCounter(ctx context.Context, addr []byte) (uint32, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.AccountKeyCounterKey(addr))
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	if len(bz) != 4 {
		return 0, fmt.Errorf("invalid key counter length: %d", len(bz))
	}
	return binary.BigEndian.Uint32(bz), nil
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

// ---------- Rotation Height ----------

// SetRotationHeight stores the block height of the last key rotation for an account.
func (k Keeper) SetRotationHeight(ctx context.Context, addr []byte, height uint64) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], height)
	return kvStore.Set(types.AccountRotationHeightKey(addr), buf[:])
}

// GetRotationHeight retrieves the block height of the last key rotation.
// Returns 0, nil if not found.
func (k Keeper) GetRotationHeight(ctx context.Context, addr []byte) (uint64, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.AccountRotationHeightKey(addr))
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	if len(bz) != 8 {
		return 0, fmt.Errorf("invalid rotation height length: %d", len(bz))
	}
	return binary.BigEndian.Uint64(bz), nil
}
