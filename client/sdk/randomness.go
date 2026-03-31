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
)

// DeriveRandomness derives deterministic randomness from the secret key and
// current on-chain state using HKDF-SHA256.
//
// Since currentBalance changes after every on-chain operation, the derived r
// is unique each time without requiring client-side persistence.
//
// Parameters:
//   - sk: the ElGamal secret key (HKDF input key material)
//   - chainID: the chain identifier (domain separation)
//   - denom: the token denomination
//   - currentBalance: the current available balance ciphertext bytes from chain (used as salt)
//   - opType: one of the Op* constants (domain separation for multi-r operations)
func DeriveRandomness(sk *fr.Element, chainID, denom string, currentBalance []byte, opType string) (fr.Element, error) {
	skBytes := sk.Bytes()

	// Salt is the current balance ciphertext — the naturally changing nonce.
	// Nil/empty is valid (e.g., first operation on a new denom).
	salt := currentBalance

	// Info provides domain separation: chainID || "/" || denom || "/" || opType
	info := make([]byte, 0, len(chainID)+1+len(denom)+1+len(opType))
	info = append(info, []byte(chainID)...)
	info = append(info, '/')
	info = append(info, []byte(denom)...)
	info = append(info, '/')
	info = append(info, []byte(opType)...)

	reader := hkdf.New(sha256.New, skBytes[:], salt, info)

	// Read 64 bytes (512 bits) for uniform distribution when reduced mod field order.
	// The BN254 scalar field is ~254 bits, so 512 bits of HKDF output gives
	// negligible bias after reduction (< 2^-258).
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
func DeriveRandomnessWithIndex(sk *fr.Element, chainID, denom string, currentBalance []byte, opType string, index uint32) (fr.Element, error) {
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], index)
	indexedOp := opType + "/" + string(idxBuf[:])
	return DeriveRandomness(sk, chainID, denom, currentBalance, indexedOp)
}
