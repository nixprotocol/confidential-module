package keeper

import (
	"context"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	sdk "github.com/cosmos/cosmos-sdk/types"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"

	"github.com/nixprotocol/confidential-module/types"
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
	var proof elgamal.EqualityProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrEqualityProofFailed.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, receiver, denom)
	if !elgamal.VerifyEquality(&proof, pk1, pk2, pk3, ct1, ct2, ct3, transcript) {
		return types.ErrEqualityProofFailed.Wrap("proof verification failed")
	}
	return nil
}

// verifyAggregateRange deserializes and verifies an aggregate range proof.
// Used for MsgConfidentialSend (sender remaining + transfer amount)
// and MsgUnshield (remaining balance).
func (k Keeper) verifyAggregateRange(ctx context.Context, proofBytes []byte, commitments []bn254.G1Affine, Hbase *bn254.G1Affine, n int, sender, receiver, denom string) error {
	var proof bulletproofs.AggregateRangeProof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrRangeProofFailed.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, receiver, denom)
	if !bulletproofs.AggregateRangeVerify(commitments, &proof, Hbase, n, transcript) {
		return types.ErrRangeProofFailed.Wrap("proof verification failed")
	}
	return nil
}

// verifyApplyPending deserializes and verifies an ApplyPending proof.
// Proves the user decrypted the pending balance and re-encrypted to a new
// available balance ciphertext.
func (k Keeper) verifyApplyPending(ctx context.Context, proofBytes []byte, pk *bn254.G1Affine, pending, newCt *elgamal.Ciphertext, sender, denom string) error {
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

// verifyEquality2 deserializes and verifies a 2-key equality proof.
// Used for MsgRotateKey to prove that old-key and new-key ciphertexts
// encrypt the same balance.
func (k Keeper) verifyEquality2(ctx context.Context, proofBytes []byte, pk1, pk2 *bn254.G1Affine, ct1, ct2 *elgamal.Ciphertext, sender, denom string) error {
	var proof elgamal.Equality2Proof
	if err := proof.Unmarshal(proofBytes); err != nil {
		return types.ErrEqualityProofFailed.Wrap("invalid proof format")
	}
	transcript := k.buildTranscript(ctx, sender, "", denom)
	if !elgamal.VerifyEquality2(&proof, pk1, pk2, ct1, ct2, transcript) {
		return types.ErrEqualityProofFailed.Wrap("proof verification failed")
	}
	return nil
}

// ---------- Helpers ----------

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

// unmarshalPublicKey parses 64 bytes into a bn254.G1Affine.
func unmarshalPublicKey(data []byte) (bn254.G1Affine, error) {
	return elgamal.UnmarshalPublicKey(data)
}

// addCiphertexts performs homomorphic addition of two serialized ciphertexts.
// Returns the serialized result (128 bytes).
func addCiphertexts(a, b []byte) ([]byte, error) {
	ctA, err := unmarshalCiphertext(a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal first ciphertext: %w", err)
	}
	ctB, err := unmarshalCiphertext(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal second ciphertext: %w", err)
	}
	result := elgamal.Add(ctA, ctB)
	return result.Marshal()
}

// subCiphertexts performs homomorphic subtraction of two serialized ciphertexts (a - b).
// Returns the serialized result (128 bytes).
func subCiphertexts(a, b []byte) ([]byte, error) {
	ctA, err := unmarshalCiphertext(a)
	if err != nil {
		return nil, fmt.Errorf("unmarshal first ciphertext: %w", err)
	}
	ctB, err := unmarshalCiphertext(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal second ciphertext: %w", err)
	}
	result := elgamal.Sub(ctA, ctB)
	return result.Marshal()
}
