package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"golang.org/x/crypto/hkdf"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"

	"github.com/nixprotocol/confidential-module/types"
)

// Gas costs for proof verification, calibrated from benchmarks on Apple M1 Pro.
// These should be tuned per-chain based on validator hardware. The ratio between
// operations should remain approximately the same across platforms.
//
// Reference latencies (M1 Pro, arm64):
//   DLEQ verify:           ~200μs
//   ApplyPending verify:   ~505μs
//   Equality verify:       ~770μs
//   Range verify (64-bit): ~5.2ms
//   Aggregate range (2×64):~9.1ms
const (
	GasDLEQVerify          = 50_000
	GasEqualityVerify      = 100_000
	GasAggregateRangeBase  = 150_000 // base cost for aggregate range proof
	GasAggregateRangePerBit = 2_000  // additional cost per bit of range
	GasApplyPendingVerify = 70_000
)

// buildTranscript creates a Fiat-Shamir transcript with chain context per spec Section 4.2.2.
func (k Keeper) buildTranscript(ctx context.Context, sender, receiver, denom string) *elgamal.Transcript {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	t := elgamal.NewTranscript("x/confidential/v1")
	t.AppendBytes("chain_id", []byte(sdkCtx.ChainID()))
	t.AppendBytes("sender", []byte(sender))
	if receiver != "" {
		t.AppendBytes("receiver", []byte(receiver))
	}
	t.AppendBytes("denom", []byte(denom))
	return t
}

// verifyDLEQ deserializes and verifies a DLEQ proof with context transcript.
// Used for MsgShield and MsgUnshield (decryption proof).
func (k Keeper) verifyDLEQ(ctx context.Context, proofBytes []byte, pk *bn254.G1Affine, ct *elgamal.Ciphertext, amount uint64, sender, denom string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	sdkCtx.GasMeter().ConsumeGas(GasDLEQVerify, "dleq proof verification")

	var proof elgamal.DLEQProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrInvalidProof.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, "", denom)
	if !elgamal.VerifyDLEQ(&proof, pk, ct, amount, transcript) {
		return types.ErrInvalidProof.Wrap("proof verification failed")
	}
	return nil
}

// verifyEquality deserializes and verifies a 3-key equality proof.
// Used for MsgConfidentialSend to prove sender, receiver, and auditor
// ciphertexts all encrypt the same amount.
func (k Keeper) verifyEquality(ctx context.Context, proofBytes []byte, pk1, pk2, pk3 *bn254.G1Affine, ct1, ct2, ct3 *elgamal.Ciphertext, sender, receiver, denom string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	sdkCtx.GasMeter().ConsumeGas(GasEqualityVerify, "equality proof verification")

	var proof elgamal.EqualityProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrInvalidProof.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, receiver, denom)
	if !elgamal.VerifyEquality(&proof, pk1, pk2, pk3, ct1, ct2, ct3, transcript) {
		return types.ErrInvalidProof.Wrap("proof verification failed")
	}
	return nil
}

// verifyAggregateRange deserializes and verifies an aggregate range proof.
// Used for MsgConfidentialSend (sender remaining + transfer amount)
// and MsgUnshield (remaining balance).
func (k Keeper) verifyAggregateRange(ctx context.Context, proofBytes []byte, commitments []bn254.G1Affine, Hbase *bn254.G1Affine, n int, sender, receiver, denom string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	// Gas scales with proof complexity: base + (bits × commitments × per_bit).
	// MsgConfidentialSend has 2 commitments (transfer + remainder), MsgUnshield has 1.
	gasCost := GasAggregateRangeBase + uint64(n)*uint64(len(commitments))*GasAggregateRangePerBit
	sdkCtx.GasMeter().ConsumeGas(gasCost, "aggregate range proof verification")

	var proof bulletproofs.AggregateRangeProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrInvalidProof.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, receiver, denom)
	if !bulletproofs.AggregateRangeVerify(commitments, &proof, Hbase, n, transcript) {
		return types.ErrInvalidProof.Wrap("proof verification failed")
	}
	return nil
}

// verifyApplyPending deserializes and verifies an ApplyPending proof.
// Proves the user decrypted the pending balance and re-encrypted to a new
// available balance ciphertext.
func (k Keeper) verifyApplyPending(ctx context.Context, proofBytes []byte, pk *bn254.G1Affine, pending, newCt *elgamal.Ciphertext, sender, denom string) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	sdkCtx.GasMeter().ConsumeGas(GasApplyPendingVerify, "apply-pending proof verification")

	var proof elgamal.ApplyPendingProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrInvalidProof.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, "", denom)
	if !elgamal.VerifyApplyPending(&proof, pk, pending, newCt, transcript) {
		return types.ErrInvalidProof.Wrap("proof verification failed")
	}
	return nil
}

// ---------- Helpers ----------

// deterministicZeroEncrypt creates an encryption of zero with deterministic
// non-zero randomness derived from chain context. The result is indistinguishable
// from a non-zero ciphertext to observers who don't know the secret key.
//
// r = SHA256(domain || addr || "/" || denom || "/" || blockHeight)
// C1 = r*G, C2 = 0*G + r*pk = r*pk
//
// All validators derive the same r from the same inputs, maintaining consensus.
func deterministicZeroEncrypt(pk *bn254.G1Affine, addr []byte, denom string, blockHeight uint64) ([]byte, error) {
	// Derive deterministic randomness from chain context using HKDF-SHA256.
	// IKM = domain tag, salt = addr + denom + height (the changing nonce).
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], blockHeight)

	salt := make([]byte, 0, len(addr)+1+len(denom)+1+8)
	salt = append(salt, addr...)
	salt = append(salt, '/')
	salt = append(salt, []byte(denom)...)
	salt = append(salt, '/')
	salt = append(salt, heightBuf[:]...)

	reader := hkdf.New(sha256.New, []byte("x/confidential/zero-encrypt"), salt, nil)

	// Read 64 bytes (512 bits) for negligible bias when reduced mod ~254-bit field.
	var buf [64]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}

	var r fr.Element
	r.SetBigInt(new(big.Int).SetBytes(buf[:]))

	// Guard against astronomically unlikely r == 0.
	if r.IsZero() {
		buf[0] ^= 0x01
		r.SetBigInt(new(big.Int).SetBytes(buf[:]))
	}

	ct, _, err := elgamal.EncryptWithRandomness(0, pk, &r)
	if err != nil {
		return nil, err
	}
	return ct.Marshal()
}

// unmarshalCiphertext parses 128 bytes into an elgamal.Ciphertext.
func unmarshalCiphertext(data []byte) (*elgamal.Ciphertext, error) {
	if len(data) != elgamal.CiphertextSize {
		return nil, fmt.Errorf("ciphertext must be %d bytes, got %d", elgamal.CiphertextSize, len(data))
	}
	var ct elgamal.Ciphertext
	if err := ct.Unmarshal(data); err != nil {
		return nil, err
	}
	return &ct, nil
}

// getRegisteredPubkey fetches and unmarshals an account's ElGamal public key
// in a single store read. Returns ErrKeyNotRegistered if no key exists, or
// propagates store/unmarshal errors directly.
func (k Keeper) getRegisteredPubkey(ctx context.Context, addr []byte) (bn254.G1Affine, error) {
	pkBytes, err := k.GetAccountPubkey(ctx, addr)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	if pkBytes == nil {
		return bn254.G1Affine{}, types.ErrKeyNotRegistered
	}
	pk, err := unmarshalPublicKey(pkBytes)
	if err != nil {
		return bn254.G1Affine{}, types.ErrInvalidPubkey.Wrap(err.Error())
	}
	return pk, nil
}

// unmarshalPublicKey parses 64 bytes into a bn254.G1Affine.
func unmarshalPublicKey(data []byte) (bn254.G1Affine, error) {
	return elgamal.UnmarshalPublicKey(data)
}

// unmarshalOrZero parses a serialized ciphertext, treating nil as the zero
// ciphertext (identity). This allows handlers to work with balances that were
// never explicitly initialized (e.g., when a denom is added after registration).
func unmarshalOrZero(data []byte) (*elgamal.Ciphertext, error) {
	if data == nil {
		var ct elgamal.Ciphertext // zero-value = identity ciphertext (O, O)
		return &ct, nil
	}
	return unmarshalCiphertext(data)
}

// addCiphertexts performs homomorphic addition of two serialized ciphertexts.
// A nil operand is treated as the zero (identity) ciphertext.
// Returns the serialized result (128 bytes).
func addCiphertexts(a, b []byte) ([]byte, error) {
	ctA, err := unmarshalOrZero(a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal first ciphertext: %w", err)
	}
	ctB, err := unmarshalOrZero(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal second ciphertext: %w", err)
	}
	result := elgamal.Add(ctA, ctB)
	return result.Marshal()
}

// subCiphertexts performs homomorphic subtraction of two serialized ciphertexts (a - b).
// A nil operand is treated as the zero (identity) ciphertext.
// Returns the serialized result (128 bytes).
func subCiphertexts(a, b []byte) ([]byte, error) {
	ctA, err := unmarshalOrZero(a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal first ciphertext: %w", err)
	}
	ctB, err := unmarshalOrZero(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal second ciphertext: %w", err)
	}
	result := elgamal.Sub(ctA, ctB)
	return result.Marshal()
}
