package sdk

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/hkdf"
)

// Operation types for domain separation in HKDF derivation.
const (
	OpShield       = "shield"
	OpSendSender   = "send/sender"
	OpSendReceiver = "send/receiver"
	OpSendAuditor  = "send/auditor"
	OpApplyPending = "apply_pending"
	OpUnshield     = "unshield"

	// Blinding factors for the Pedersen commitments the range proofs are taken
	// over. Separate domains so they never coincide with a ciphertext randomness.
	OpSendTransferBlinding      = "send/blinding/transfer"
	OpSendRemainingBlinding     = "send/blinding/remaining"
	OpUnshieldRemainingBlinding = "unshield/blinding/remaining"
)

// DerivationContext identifies the exact operation randomness is being derived
// for.
//
// Every field that can differ between two transactions must appear here. The
// balance ciphertext alone is not enough: it only changes once a transaction
// lands, so two transactions built from the same snapshot derive the same r.
// Two ElGamal ciphertexts under the same key with the same r publicly leak the
// difference of their plaintexts, because
//
//	ct_A - ct_B = (O, (v_A - v_B)*G)
//
// and both can sit in the mempool at the same time.
//
// Sequence alone does not close this: a transaction that gets evicted and
// rebuilt at a different amount reuses the same account sequence. Binding
// Amount and Receiver is what covers that case — differing content yields
// differing r, while genuinely identical content yields an identical
// ciphertext, which leaks nothing since there is nothing to compare it against.
// Sequence still earns its place for the reverse case: identical content
// resubmitted as a distinct transaction.
type DerivationContext struct {
	ChainID  string
	Denom    string
	Op       string // one of the Op* constants
	Sequence uint64 // sending account's sequence number
	Amount   uint64 // amount being encrypted; 0 where not applicable
	Receiver string // receiver address; "" where not applicable
}

// encode renders the context as unambiguous HKDF info. Every variable-length
// field is length-prefixed so two distinct contexts cannot produce the same
// byte string.
func (c DerivationContext) encode() []byte {
	out := make([]byte, 0, 64+len(c.ChainID)+len(c.Denom)+len(c.Op)+len(c.Receiver))

	appendField := func(b []byte) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
		out = append(out, lenBuf[:]...)
		out = append(out, b...)
	}
	appendField([]byte(c.ChainID))
	appendField([]byte(c.Denom))
	appendField([]byte(c.Op))
	appendField([]byte(c.Receiver))

	var num [8]byte
	binary.BigEndian.PutUint64(num[:], c.Sequence)
	out = append(out, num[:]...)
	binary.BigEndian.PutUint64(num[:], c.Amount)
	out = append(out, num[:]...)

	return out
}

// DeriveRandomness derives deterministic randomness from the secret key, the
// current on-chain state, and the full operation context using HKDF-SHA256.
//
// Determinism is deliberate: it lets a wallet re-derive its blinding factors
// from chain state alone, without client-side persistence. See
// DerivationContext for what the context must cover and why.
func DeriveRandomness(sk *fr.Element, currentBalance []byte, ctx DerivationContext) (fr.Element, error) {
	skBytes := sk.Bytes()

	// Salt is the current balance ciphertext — the naturally changing nonce.
	// Nil/empty is valid (e.g., first operation on a new denom).
	reader := hkdf.New(sha256.New, skBytes[:], currentBalance, ctx.encode())

	// Read 64 bytes (512 bits) for uniform distribution when reduced mod field
	// order. The BN254 scalar field is ~254 bits, so 512 bits of HKDF output
	// gives negligible bias after reduction (< 2^-258).
	var buf [64]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return fr.Element{}, fmt.Errorf("hkdf read: %w", err)
	}

	var r fr.Element
	var rBig big.Int
	rBig.SetBytes(buf[:])
	r.SetBigInt(&rBig) // reduces mod field order
	return r, nil
}

// DeriveRandomnessWithIndex is like DeriveRandomness but appends a uint32 index
// to the operation type. Useful when multiple randomness values are needed for
// the same operation (e.g., nonces inside proofs).
func DeriveRandomnessWithIndex(sk *fr.Element, currentBalance []byte, ctx DerivationContext, index uint32) (fr.Element, error) {
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], index)
	ctx.Op = ctx.Op + "/" + string(idxBuf[:])
	return DeriveRandomness(sk, currentBalance, ctx)
}
