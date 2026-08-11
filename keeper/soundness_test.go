package keeper_test

import (
	"crypto/rand"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// TestRangeProofBlindingBaseIsNotAnAccountKey guards the root cause of the mint
// vulnerability: the range proof's blinding base must be a nothing-up-my-sleeve
// generator, never a key any account controls.
func TestRangeProofBlindingBaseIsNotAnAccountKey(t *testing.T) {
	base := keeper.RangeProofBlindingBase()

	require.True(t, base.Equal(&bulletproofs.H), "blinding base must be the NUMS generator")
	require.False(t, base.IsInfinity())
	require.True(t, base.IsOnCurve())

	// It must not coincide with a freshly generated account key.
	for i := 0; i < 8; i++ {
		_, pk, err := elgamal.KeyGen(rand.Reader)
		require.NoError(t, err)
		require.False(t, base.Equal(&pk), "blinding base collided with an account key")
	}
}

// TestConfidentialSend_CannotOverdraw is the regression test for the mint
// vulnerability.
//
// Alice shields 1,000 and then tries to send 5,000,000. Every other proof in the
// message is honest: the three ciphertexts really do encrypt 5,000,000 and the
// equality proof is valid. Only the remaining balance is a lie — it is actually
// 1,000 - 5,000,000, and she claims it is 0.
//
// Previously this succeeded. The range proof was taken over the ElGamal C2,
// whose blinding base was Alice's own public key; knowing her secret key she
// could re-open that "commitment" to any value, so the range proof constrained
// nothing and the module account could be drained.
func TestConfidentialSend_CannotOverdraw(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
	}))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice, bob := aliceAddr.String(), bobAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 10000)

	registerKey(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)
	registerKey(t, msgServer, k, ctx, bob, &bobSk, &bobPk)

	// Alice shields her entire holding: 1,000.
	const shieldAmount = uint64(1000)
	shieldR := randScalar(t)
	shieldCt, _, err := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	require.NoError(t, err)
	shieldProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &shieldCt, shieldAmount,
		k.BuildTranscriptForTest(ctx, alice, "", "uatom"), rand.Reader)
	require.NoError(t, err)
	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender: alice, Denom: "uatom", Amount: "1000",
		Ciphertext: shieldCt.Marshal(), Proof: shieldProof.Marshal(),
	})
	require.NoError(t, err)

	// Alice attempts to send 5,000,000 she does not have.
	const sendAmount = uint64(5_000_000)
	rSender, rReceiver, rAuditor := randScalar(t), randScalar(t), randScalar(t)

	senderCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rSender)
	require.NoError(t, err)
	receiverCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rReceiver)
	require.NoError(t, err)
	auditorCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &auditorPk, &rAuditor)
	require.NoError(t, err)

	// Honest equality proof: all three really do encrypt 5,000,000.
	eqProof, err := elgamal.ProveEquality(sendAmount, &rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk, &senderCt, &receiverCt, &auditorCt,
		k.BuildTranscriptForTest(ctx, alice, bob, "uatom"), rand.Reader)
	require.NoError(t, err)

	// Claim the remaining balance is 0 when it is really 1,000 - 5,000,000.
	var remainingR fr.Element
	remainingR.Sub(&shieldR, &rSender)
	sp := buildSendProofs(t, k, ctx, alice, bob, "uatom", &alicePk,
		&senderCt, &shieldCt, sendAmount, 0, &rSender, &remainingR, 64)

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender: alice, Receiver: bob, Denom: "uatom",
		SenderUpdate:             senderCt.Marshal(),
		ReceiverUpdate:           receiverCt.Marshal(),
		AuditorUpdate:            auditorCt.Marshal(),
		RangeProof:               sp.RangeProof,
		EqualityProof:            eqProof.Marshal(),
		TransferCommitment:       sp.TransferCommitment,
		RemainingCommitment:      sp.RemainingCommitment,
		TransferCommitmentProof:  sp.TransferCommitmentProof,
		RemainingCommitmentProof: sp.RemainingCommitmentProof,
	})
	require.Error(t, err, "a 5,000,000 send from an account holding 1,000 must be rejected")
	require.ErrorIs(t, err, types.ErrInvalidProof)

	// Nothing moved: Bob has no pending balance and no tokens were minted.
	bobPending, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.Nil(t, bobPending)
	require.Equal(t, sdkmath.NewInt(9000), bankKeeper.balances[alice]["uatom"])
}

// TestRegisterKey_RequiresProofOfPossession checks that an account cannot bind
// itself to a public key it does not hold the secret for — including by copying
// another account's registered key.
func TestRegisterKey_RequiresProofOfPossession(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
	}))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	mallory := sdk.AccAddress([]byte("mallory_____________")).String()

	registerKey(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// No proof at all.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: mallory,
		Pubkey: elgamal.MarshalPublicKey(&alicePk),
	})
	require.Error(t, err)

	// Alice's proof of possession replayed by Mallory: the transcript binds the
	// registering address, so it does not transfer.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: mallory,
		Pubkey: elgamal.MarshalPublicKey(&alicePk),
		Pop:    popFor(t, k, ctx, alice, &aliceSk, &alicePk),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidProof)

	// Mallory registering a key she does hold succeeds.
	malSk, malPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	registerKey(t, msgServer, k, ctx, mallory, &malSk, &malPk)
}
