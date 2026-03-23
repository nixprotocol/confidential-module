package types

import "encoding/binary"

const (
	ModuleName        = "confidential"
	StoreKey          = ModuleName
	ModuleAccountName = ModuleName
)

// Store key prefixes.
var (
	// Account public key: prefix + addr
	accountPubkeyPrefix = []byte("confidential/pk/")
	// Account key counter: prefix + addr
	accountKeyCounterPrefix = []byte("confidential/kc/")
	// Available (main) balance: prefix + addr + "/" + denom
	availableBalancePrefix = []byte("confidential/ab/")
	// Pending balance: prefix + addr + "/" + denom
	pendingBalancePrefix = []byte("confidential/pb/")
	// Module params
	paramsKey = []byte("confidential/params")
	// Account rotation height: prefix + addr
	accountRotationHeightPrefix = []byte("confidential/rh/")
	// Pending-is-zero flag: prefix + addr + "/" + denom
	pendingIsZeroPrefix = []byte("confidential/pz/")
)

// Key accessor functions — each returns a fresh slice to avoid append mutation.

func ParamsKeyBytes() []byte { return copyBytes(paramsKey) }

// Prefix accessors for iteration during genesis export.
func AccountPubkeyPrefix() []byte          { return copyBytes(accountPubkeyPrefix) }
func AccountKeyCounterPrefix() []byte      { return copyBytes(accountKeyCounterPrefix) }
func AvailableBalancePrefix() []byte        { return copyBytes(availableBalancePrefix) }
func PendingBalancePrefix() []byte          { return copyBytes(pendingBalancePrefix) }
func AccountRotationHeightPrefix() []byte   { return copyBytes(accountRotationHeightPrefix) }
func PendingIsZeroPrefix() []byte            { return copyBytes(pendingIsZeroPrefix) }

// AccountPubkeyKey returns the store key for an account's public key.
func AccountPubkeyKey(addr []byte) []byte {
	return appendBytes(accountPubkeyPrefix, addr)
}

// AccountKeyCounterKey returns the store key for an account's key counter.
func AccountKeyCounterKey(addr []byte) []byte {
	return appendBytes(accountKeyCounterPrefix, addr)
}

// AvailableBalanceKey returns the store key for an account's available balance
// for a given denomination.
func AvailableBalanceKey(addr []byte, denom string) []byte {
	key := make([]byte, len(availableBalancePrefix)+len(addr)+1+len(denom))
	copy(key, availableBalancePrefix)
	copy(key[len(availableBalancePrefix):], addr)
	key[len(availableBalancePrefix)+len(addr)] = '/'
	copy(key[len(availableBalancePrefix)+len(addr)+1:], denom)
	return key
}

// PendingBalanceKey returns the store key for an account's pending balance
// for a given denomination.
func PendingBalanceKey(addr []byte, denom string) []byte {
	key := make([]byte, len(pendingBalancePrefix)+len(addr)+1+len(denom))
	copy(key, pendingBalancePrefix)
	copy(key[len(pendingBalancePrefix):], addr)
	key[len(pendingBalancePrefix)+len(addr)] = '/'
	copy(key[len(pendingBalancePrefix)+len(addr)+1:], denom)
	return key
}

// AccountRotationHeightKey returns the store key for an account's last rotation
// block height.
func AccountRotationHeightKey(addr []byte) []byte {
	return appendBytes(accountRotationHeightPrefix, addr)
}

// PendingIsZeroKey returns the store key for the pending-is-zero flag
// for an account and denomination.
func PendingIsZeroKey(addr []byte, denom string) []byte {
	key := make([]byte, len(pendingIsZeroPrefix)+len(addr)+1+len(denom))
	copy(key, pendingIsZeroPrefix)
	copy(key[len(pendingIsZeroPrefix):], addr)
	key[len(pendingIsZeroPrefix)+len(addr)] = '/'
	copy(key[len(pendingIsZeroPrefix)+len(addr)+1:], denom)
	return key
}

// helpers that always allocate fresh slices

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func appendBytes(prefix, suffix []byte) []byte {
	key := make([]byte, len(prefix)+len(suffix))
	copy(key, prefix)
	copy(key[len(prefix):], suffix)
	return key
}

func appendUint64(prefix []byte, v uint64) []byte {
	key := make([]byte, len(prefix)+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix):], v)
	return key
}

// Ensure binary import is used.
var _ = binary.BigEndian
