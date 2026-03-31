package keeper

import (
	"context"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// DeterministicZeroEncryptForTest exports deterministicZeroEncrypt for testing.
func DeterministicZeroEncryptForTest(pk *bn254.G1Affine, addr []byte, denom string, blockHeight uint64) ([]byte, error) {
	return deterministicZeroEncrypt(pk, addr, denom, blockHeight)
}

// BuildTranscriptForTest is a test-only export of the private buildTranscript method.
func (k Keeper) BuildTranscriptForTest(ctx context.Context, sender, receiver, denom string) *elgamal.Transcript {
	return k.buildTranscript(ctx, sender, receiver, denom)
}

