package keeper

import (
	"context"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// BuildTranscriptForTest is a test-only export of the private buildTranscript method.
func (k Keeper) BuildTranscriptForTest(ctx context.Context, sender, receiver, denom string) *elgamal.Transcript {
	return k.buildTranscript(ctx, sender, receiver, denom)
}
