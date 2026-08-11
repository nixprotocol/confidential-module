package keeper_test

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	confidentialcrypto "github.com/nixprotocol/confidential-module/crypto"
	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// randScalar returns a fresh non-zero scalar.
func randScalar(t *testing.T) fr.Element {
	t.Helper()
	var e fr.Element
	_, err := e.SetRandom()
	require.NoError(t, err)
	return e
}

// popFor builds the proof of possession MsgRegisterKey requires.
func popFor(t *testing.T, k keeper.Keeper, ctx sdk.Context, sender string, sk *fr.Element, pk *bn254.G1Affine) []byte {
	t.Helper()
	proof, err := elgamal.ProvePossession(sk, pk, k.BuildTranscriptForTest(ctx, sender, "", ""), rand.Reader)
	require.NoError(t, err)
	return proof.Marshal()
}

// registerKey registers an account key with a valid proof of possession.
func registerKey(t *testing.T, msgServer types.MsgServer, k keeper.Keeper, ctx sdk.Context,
	sender string, sk *fr.Element, pk *bn254.G1Affine) {
	t.Helper()
	_, err := msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: sender,
		Pubkey: elgamal.MarshalPublicKey(pk),
		Pop:    popFor(t, k, ctx, sender, sk, pk),
	})
	require.NoError(t, err)
}

// sendProofs holds the commitment/range material for a MsgConfidentialSend.
type sendProofs struct {
	TransferCommitment       []byte
	RemainingCommitment      []byte
	TransferCommitmentProof  []byte
	RemainingCommitmentProof []byte
	RangeProof               []byte
}

// buildSendProofs produces the binding Pedersen commitments, the proofs tying
// them to their ciphertexts, and the aggregate range proof over them.
//
// availCt must be the sender's stored available balance; the chain derives the
// remaining-balance ciphertext as availCt - senderCt, and the commitment has to
// be bound to exactly that.
func buildSendProofs(
	t *testing.T, k keeper.Keeper, ctx sdk.Context,
	sender, receiver, denom string,
	senderPk *bn254.G1Affine,
	senderCt, availCt *elgamal.Ciphertext,
	amount, remainingAmount uint64,
	rSender, remainingR *fr.Element,
	maxBits int,
) sendProofs {
	t.Helper()

	sTransfer := randScalar(t)
	sRemaining := randScalar(t)

	transferCommitment, transferProof, err := confidentialcrypto.ProveCommitment(
		amount, rSender, &sTransfer, senderPk, senderCt,
		confidentialcrypto.RoleTransfer,
		k.BuildTranscriptForTest(ctx, sender, receiver, denom), rand.Reader)
	require.NoError(t, err)

	remainingCt := elgamal.Sub(availCt, senderCt)
	remainingCommitment, remainingProof, err := confidentialcrypto.ProveCommitment(
		remainingAmount, remainingR, &sRemaining, senderPk, &remainingCt,
		confidentialcrypto.RoleRemaining,
		k.BuildTranscriptForTest(ctx, sender, receiver, denom), rand.Reader)
	require.NoError(t, err)

	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{amount, remainingAmount},
		[]*fr.Element{&sTransfer, &sRemaining},
		confidentialcrypto.BlindingBase(), maxBits,
		k.BuildTranscriptForTest(ctx, sender, receiver, denom))
	require.NoError(t, err)
	rangeProofBytes, err := aggProof.Marshal()
	require.NoError(t, err)

	return sendProofs{
		TransferCommitment:       transferCommitment,
		RemainingCommitment:      remainingCommitment,
		TransferCommitmentProof:  transferProof,
		RemainingCommitmentProof: remainingProof,
		RangeProof:               rangeProofBytes,
	}
}

// unshieldProofs holds the commitment/range material for a MsgUnshield.
type unshieldProofs struct {
	RemainingCommitment      []byte
	RemainingCommitmentProof []byte
	RangeProof               []byte
}

// buildUnshieldProofs produces the remaining-balance commitment, its binding
// proof, and the range proof over it.
func buildUnshieldProofs(
	t *testing.T, k keeper.Keeper, ctx sdk.Context,
	sender, denom string,
	pk *bn254.G1Affine,
	ct, availCt *elgamal.Ciphertext,
	remainingAmount uint64,
	remainingR *fr.Element,
	maxBits int,
) unshieldProofs {
	t.Helper()

	sRemaining := randScalar(t)

	remainingCt := elgamal.Sub(availCt, ct)
	remainingCommitment, remainingProof, err := confidentialcrypto.ProveCommitment(
		remainingAmount, remainingR, &sRemaining, pk, &remainingCt,
		confidentialcrypto.RoleRemaining,
		k.BuildTranscriptForTest(ctx, sender, "", denom), rand.Reader)
	require.NoError(t, err)

	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{remainingAmount},
		[]*fr.Element{&sRemaining},
		confidentialcrypto.BlindingBase(), maxBits,
		k.BuildTranscriptForTest(ctx, sender, "", denom))
	require.NoError(t, err)
	rangeProofBytes, err := aggProof.Marshal()
	require.NoError(t, err)

	return unshieldProofs{
		RemainingCommitment:      remainingCommitment,
		RemainingCommitmentProof: remainingProof,
		RangeProof:               rangeProofBytes,
	}
}
