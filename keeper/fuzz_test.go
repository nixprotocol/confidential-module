package keeper_test

import (
	"crypto/rand"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// ---------------------------------------------------------------------------
// Shared fixtures — initialized once, reused by all fuzz targets that need
// valid cryptographic objects alongside fuzzed proof bytes.
// ---------------------------------------------------------------------------

var (
	fuzzOnce sync.Once
	fuzzPk1  bn254.G1Affine
	fuzzPk2  bn254.G1Affine
	fuzzPk3  bn254.G1Affine
	fuzzCt1  elgamal.Ciphertext
	fuzzCt2  elgamal.Ciphertext
	fuzzCt3  elgamal.Ciphertext
)

func ensureFuzzFixtures() {
	fuzzOnce.Do(func() {
		_, pk1, err := elgamal.KeyGen(rand.Reader)
		if err != nil {
			panic(err)
		}
		_, pk2, err := elgamal.KeyGen(rand.Reader)
		if err != nil {
			panic(err)
		}
		_, pk3, err := elgamal.KeyGen(rand.Reader)
		if err != nil {
			panic(err)
		}
		fuzzPk1, fuzzPk2, fuzzPk3 = pk1, pk2, pk3

		ct1, _, err := elgamal.Encrypt(42, &pk1, rand.Reader)
		if err != nil {
			panic(err)
		}
		ct2, _, err := elgamal.Encrypt(42, &pk2, rand.Reader)
		if err != nil {
			panic(err)
		}
		ct3, _, err := elgamal.Encrypt(42, &pk3, rand.Reader)
		if err != nil {
			panic(err)
		}
		fuzzCt1, fuzzCt2, fuzzCt3 = ct1, ct2, ct3
	})
}

// ---------------------------------------------------------------------------
// Unmarshal fuzz targets — ensure no panics on arbitrary bytes.
// These are the critical first line of defense: if any of these panic,
// a malformed transaction will crash the validator node.
// ---------------------------------------------------------------------------

func FuzzUnmarshalPublicKey(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = elgamal.UnmarshalPublicKey(data)
	})
}

func FuzzUnmarshalCiphertext(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ct elgamal.Ciphertext
		_ = ct.Unmarshal(data)
	})
}

func FuzzDLEQProofUnmarshal(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 160)) // DLEQProofSize

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.DLEQProof
		_ = proof.Unmarshal(data)
	})
}

func FuzzEqualityProofUnmarshal(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 512)) // EqualityProofSize

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.EqualityProof
		_ = proof.Unmarshal(data)
	})
}

func FuzzApplyPendingProofUnmarshal(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 352)) // ApplyPendingProofSize

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.ApplyPendingProof
		_ = proof.Unmarshal(data)
	})
}

func FuzzAggregateRangeProofUnmarshal(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 4))                  // just header
	f.Add(make([]byte, 228))                // header + min IP
	f.Add(append([]byte{0, 0, 0, 7}, make([]byte, 700)...)) // 7 rounds + data

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof bulletproofs.AggregateRangeProof
		_ = proof.Unmarshal(data)
	})
}

// ---------------------------------------------------------------------------
// Verify fuzz targets — ensure no panics when a successfully-unmarshaled
// (but invalid) proof is passed to the verify function with valid keys and
// ciphertexts. The expected result is verify returning false, never a panic.
// ---------------------------------------------------------------------------

func FuzzDLEQVerify(f *testing.F) {
	ensureFuzzFixtures()

	f.Add(make([]byte, 160))

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.DLEQProof
		if err := proof.Unmarshal(data); err != nil {
			return
		}
		// Must not panic — just return true/false.
		elgamal.VerifyDLEQ(&proof, &fuzzPk1, &fuzzCt1, 42, nil)
	})
}

func FuzzEqualityVerify(f *testing.F) {
	ensureFuzzFixtures()

	f.Add(make([]byte, 512))

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.EqualityProof
		if err := proof.Unmarshal(data); err != nil {
			return
		}
		elgamal.VerifyEquality(&proof, &fuzzPk1, &fuzzPk2, &fuzzPk3, &fuzzCt1, &fuzzCt2, &fuzzCt3, nil)
	})
}

func FuzzApplyPendingVerify(f *testing.F) {
	ensureFuzzFixtures()

	f.Add(make([]byte, 352))

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof elgamal.ApplyPendingProof
		if err := proof.Unmarshal(data); err != nil {
			return
		}
		elgamal.VerifyApplyPending(&proof, &fuzzPk1, &fuzzCt1, &fuzzCt2, nil)
	})
}

func FuzzAggregateRangeVerify(f *testing.F) {
	ensureFuzzFixtures()

	f.Add(make([]byte, 228))

	f.Fuzz(func(t *testing.T, data []byte) {
		var proof bulletproofs.AggregateRangeProof
		if err := proof.Unmarshal(data); err != nil {
			return
		}
		commitments := []bn254.G1Affine{fuzzCt1.C2}
		bulletproofs.AggregateRangeVerify(commitments, &proof, &fuzzPk1, 64, nil)
	})
}
