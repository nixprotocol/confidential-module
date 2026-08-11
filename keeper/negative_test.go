package keeper_test

import (
	"crypto/rand"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"

	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
)

// ---------------------------------------------------------------------------
// Helpers shared across negative tests
// ---------------------------------------------------------------------------

// defaultParams returns test params with auditor key set.
func defaultParams(auditorPk []byte) types.Params {
	return types.Params{
		AuditorPubKey:   auditorPk,
		MaxTransferBits: 64,
	}
}

// registerAccount is a convenience that registers a valid key for addr with the
// given public key. It assumes params (with auditor + enabled denoms) are already set.
func registerAccount(t *testing.T, msgServer types.MsgServer, k keeper.Keeper, ctx sdk.Context,
	addr string, sk *fr.Element, pk *bn254.G1Affine) {
	t.Helper()
	_, err := msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: addr,
		Pubkey: elgamal.MarshalPublicKey(pk),
		Pop:    popFor(t, k, ctx, addr, sk, pk),
	})
	require.NoError(t, err)
}

// shieldAccount performs a valid shield of `amount` for the given account.
// Requires the account to already be registered.
func shieldAccount(
	t *testing.T,
	k keeper.Keeper,
	msgServer types.MsgServer,
	ctx sdk.Context,
	sk fr.Element,
	pk bn254.G1Affine,
	addr string,
	amount uint64,
) fr.Element {
	t.Helper()

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	ct, _, err := elgamal.EncryptWithRandomness(amount, &pk, &r)
	require.NoError(t, err)
	ctBytes := ct.Marshal()

	transcript := k.BuildTranscriptForTest(ctx, addr, "", "uatom")
	proof, err := elgamal.ProveDLEQ(&sk, &pk, &ct, amount, transcript, nil)
	require.NoError(t, err)
	proofBytes := proof.Marshal()

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     addr,
		Denom:      "uatom",
		Amount:     sdkmath.NewIntFromUint64(amount).String(),
		Ciphertext: ctBytes,
		Proof:      proofBytes,
	})
	require.NoError(t, err)
	return r
}

// ===========================================================================
// MsgRegisterKey errors
// ===========================================================================

func TestRegisterKey_InvalidPubkey(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()

	// 32 bytes instead of 64 — should fail ValidateBasic or handler.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice,
		Pubkey: make([]byte, 32),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidPubkey)
}

func TestRegisterKey_IdentityPubkey(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()

	// All-zeros 64 bytes = identity point in uncompressed form.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice,
		Pubkey: make([]byte, 64),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidPubkey)
}

func TestRegisterKey_AlreadyRegistered(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	pkBytes := elgamal.MarshalPublicKey(&alicePk)

	// First registration succeeds.
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// Second registration should fail.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice,
		Pubkey: pkBytes,
		Pop:    popFor(t, k, ctx, alice, &aliceSk, &alicePk),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyAlreadyRegistered)
}

// ===========================================================================
// MsgShield errors
// ===========================================================================

func TestShield_NotRegistered(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()

	// Shield without registering.
	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "1000",
		Ciphertext: make([]byte, 128),
		Proof:      make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyNotRegistered)
}

func TestShield_ZeroAmount(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "0",
		Ciphertext: make([]byte, 128),
		Proof:      make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidAmount)
}

func TestShield_InvalidProof(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// Create a valid ciphertext for amount=1000, but generate proof with wrong amount=500.
	var r fr.Element
	_, err = r.SetRandom()
	require.NoError(t, err)

	ct, _, err := elgamal.EncryptWithRandomness(1000, &alicePk, &r)
	require.NoError(t, err)
	ctBytes := ct.Marshal()

	// Prove with wrong amount (500 instead of 1000).
	transcript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	wrongProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &ct, 500, transcript, nil)
	require.NoError(t, err)
	wrongProofBytes := wrongProof.Marshal()

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "1000",
		Ciphertext: ctBytes,
		Proof:      wrongProofBytes,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidProof)
}

// ===========================================================================
// MsgConfidentialSend errors
// ===========================================================================

func TestSend_ReceiverNotRegistered(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bob := sdk.AccAddress([]byte("bob_________________")).String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// Shield first so Alice has balance.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Bob is NOT registered. Send to Bob should fail.
	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       bob,
		Denom:          "uatom",
		SenderUpdate:   make([]byte, 128),
		ReceiverUpdate: make([]byte, 128),
		AuditorUpdate:  make([]byte, 128),
		RangeProof:     make([]byte, 100),
		EqualityProof:  make([]byte, elgamal.EqualityProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyNotRegistered)
}

func TestSend_InvalidEqualityProof(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bob := sdk.AccAddress([]byte("bob_________________")).String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)
	registerAccount(t, msgServer, k, ctx, bob, &bobSk, &bobPk)

	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Create valid ciphertexts but an invalid (tampered) equality proof.
	sendAmount := uint64(300)
	var rSender, rReceiver, rAuditor fr.Element
	_, _ = rSender.SetRandom()
	_, _ = rReceiver.SetRandom()
	_, _ = rAuditor.SetRandom()

	senderCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rSender)
	require.NoError(t, err)
	receiverCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rReceiver)
	require.NoError(t, err)
	auditorCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &auditorPk, &rAuditor)
	require.NoError(t, err)

	senderCtBytes := senderCt.Marshal()
	receiverCtBytes := receiverCt.Marshal()
	auditorCtBytes := auditorCt.Marshal()

	// Generate a valid equality proof then tamper with it.
	eqTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	eqProof, err := elgamal.ProveEquality(
		sendAmount,
		&rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk,
		&senderCt, &receiverCt, &auditorCt,
		eqTranscript,
		nil,
	)
	require.NoError(t, err)
	proofBytes := eqProof.Marshal()

	// Tamper: flip a byte in the middle of the proof.
	proofBytes[len(proofBytes)/2] ^= 0xFF

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       bob,
		Denom:          "uatom",
		SenderUpdate:   senderCtBytes,
		ReceiverUpdate: receiverCtBytes,
		AuditorUpdate:  auditorCtBytes,
		RangeProof:     make([]byte, 100), // will not reach range proof verification
		EqualityProof:  proofBytes,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidProof)
}

func TestSend_SelfSend(t *testing.T) {
	// ValidateBasic rejects sender == receiver.
	alice := sdk.AccAddress([]byte("alice_______________")).String()

	msg := &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       alice,
		Denom:          "uatom",
		SenderUpdate:   make([]byte, 128),
		ReceiverUpdate: make([]byte, 128),
		AuditorUpdate:  make([]byte, 128),
		RangeProof:     make([]byte, 100),
		EqualityProof:  make([]byte, elgamal.EqualityProofSize),
	}
	err := msg.ValidateBasic()
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidAmount) // "sender and receiver must be different"
}

// ===========================================================================
// MsgApplyPending errors
// ===========================================================================

func TestApplyPending_NothingPending(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// ApplyPending when PendingIsZero is true (just registered, nothing received).
	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             alice,
		Denom:              "uatom",
		NewAvailableUpdate: make([]byte, 128),
		Proof:              make([]byte, 100),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrNothingPending)
}

func TestApplyPending_NotRegistered(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             alice,
		Denom:              "uatom",
		NewAvailableUpdate: make([]byte, 128),
		Proof:              make([]byte, 100),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyNotRegistered)
}

// ===========================================================================
// MsgUnshield errors
// ===========================================================================

func TestUnshield_ExceedsBalance(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	// Shield 100.
	shieldR := shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 100)
	availCt, _, err := elgamal.EncryptWithRandomness(100, &alicePk, &shieldR)
	require.NoError(t, err)

	// Try to unshield 500 with only 100 available. Everything except the
	// remaining balance is honest: the ciphertext really does encrypt 500 and
	// the DLEQ proof is valid.
	var r fr.Element
	_, _ = r.SetRandom()
	ct, _, err := elgamal.EncryptWithRandomness(500, &alicePk, &r)
	require.NoError(t, err)
	ctBytes := ct.Marshal()

	transcript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	dleqProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &ct, 500, transcript, nil)
	require.NoError(t, err)
	dleqBytes := dleqProof.Marshal()

	// The real remaining balance is 100 - 500 = -400, which no range proof can
	// cover. So claim it is 0 instead. Before commitments were bound to their
	// ciphertexts this succeeded: the sender knows sk, so the ElGamal C2 could
	// be re-opened to any value and the range proof was vacuous.
	var remainingR fr.Element
	remainingR.Sub(&shieldR, &r)
	up := buildUnshieldProofs(t, k, ctx, alice, "uatom", &alicePk,
		&ct, &availCt, 0, &remainingR, 64)

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:                   alice,
		Denom:                    "uatom",
		Amount:                   "500",
		Ciphertext:               ctBytes,
		RangeProof:               up.RangeProof,
		DecryptionProof:          dleqBytes,
		RemainingCommitment:      up.RemainingCommitment,
		RemainingCommitmentProof: up.RemainingCommitmentProof,
	})
	require.Error(t, err, "overdrawing must be rejected")
	require.ErrorIs(t, err, types.ErrInvalidProof)
}

func TestUnshield_ZeroAmount(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          alice,
		Denom:           "uatom",
		Amount:          "0",
		Ciphertext:      make([]byte, 128),
		RangeProof:      make([]byte, 100),
		DecryptionProof: make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidAmount)
}

// ===========================================================================
// MsgSetAuditorKey errors
// ===========================================================================

func TestSetAuditorKey_Unauthorized(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, newPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// Use a random non-governance address.
	imposter := sdk.AccAddress([]byte("imposter____________")).String()

	_, err = msgServer.SetAuditorKey(ctx, &types.MsgSetAuditorKey{
		Authority: imposter,
		Pubkey:    elgamal.MarshalPublicKey(&newPk),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestSetAuditorKey_InvalidPubkey(t *testing.T) {
	// The authority address used in setupTestKeeper is "authority___________" (20 bytes).
	authority := sdk.AccAddress([]byte("authority___________")).String()

	// 32 bytes instead of 64.
	// ValidateBasic checks length == 64, so this fails at ValidateBasic.
	msg := &types.MsgSetAuditorKey{
		Authority: authority,
		Pubkey:    make([]byte, 32),
	}
	err := msg.ValidateBasic()
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidPubkey)
}

func TestSetAuditorKey_InvalidPubkeyIdentity(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	// The authority address used in setupTestKeeper.
	authority := sdk.AccAddress([]byte("authority___________")).String()

	// 64 bytes of zeros = identity point.
	_, err := msgServer.SetAuditorKey(ctx, &types.MsgSetAuditorKey{
		Authority: authority,
		Pubkey:    make([]byte, 64),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidPubkey)
}

// ---------------------------------------------------------------------------
// deterministicZeroEncrypt
// ---------------------------------------------------------------------------

func TestDeterministicZeroEncrypt_NonTrivial(t *testing.T) {
	_, pk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	addr := []byte("alice_______________")
	ct, err := keeper.DeterministicZeroEncryptForTest(&pk, addr, "uatom", 100)
	require.NoError(t, err)
	require.Len(t, ct, 128)

	// Must NOT be the identity ciphertext (all zeros).
	allZero := make([]byte, 128)
	require.NotEqual(t, allZero, ct, "zero ciphertext must not be identity (O, O)")

	// Must be deterministic: same inputs → same output.
	ct2, err := keeper.DeterministicZeroEncryptForTest(&pk, addr, "uatom", 100)
	require.NoError(t, err)
	require.Equal(t, ct, ct2, "same inputs must produce same ciphertext")

	// Different block height → different ciphertext.
	ct3, err := keeper.DeterministicZeroEncryptForTest(&pk, addr, "uatom", 101)
	require.NoError(t, err)
	require.NotEqual(t, ct, ct3, "different block height must produce different ciphertext")
}

// ---------------------------------------------------------------------------
// MsgUnshield: not registered
// ---------------------------------------------------------------------------

func TestUnshield_NotRegistered(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	// Try to unshield without registering.
	unregistered := sdk.AccAddress([]byte("unregistered________")).String()
	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          unregistered,
		Denom:           "uatom",
		Amount:          "100",
		Ciphertext:      make([]byte, 128),
		RangeProof:      make([]byte, 228),
		DecryptionProof: make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyNotRegistered)
}

// ---------------------------------------------------------------------------
// MsgConfidentialSend: wrong auditor key
// ---------------------------------------------------------------------------

func TestSend_WrongAuditorKey(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, wrongAuditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// Set params with the real auditor key.
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	bob := sdk.AccAddress([]byte("bob_________________")).String()
	bankKeeper.fundAccount(alice, "uatom", 10000)

	registerAccount(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)
	registerAccount(t, msgServer, k, ctx, bob, &bobSk, &bobPk)

	// Shield first so Alice has a balance.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Build a send with the WRONG auditor key.
	sendAmount := uint64(100)
	var rS, rR, rA fr.Element
	_, _ = rS.SetRandom()
	_, _ = rR.SetRandom()
	_, _ = rA.SetRandom()

	sCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rS)
	rCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rR)
	// Encrypt auditor ciphertext under the WRONG key.
	aCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &wrongAuditorPk, &rA)

	eqT := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	// Equality proof uses wrong auditor pk — should fail verification on-chain.
	eqProof, err := elgamal.ProveEquality(
		sendAmount,
		&rS, &rR, &rA,
		&alicePk, &bobPk, &wrongAuditorPk,
		&sCt, &rCt, &aCt,
		eqT,
		nil,
	)
	require.NoError(t, err)

	sB := sCt.Marshal()
	rB := rCt.Marshal()
	aB := aCt.Marshal()

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       bob,
		Denom:          "uatom",
		SenderUpdate:   sB,
		ReceiverUpdate: rB,
		AuditorUpdate:  aB,
		EqualityProof:  eqProof.Marshal(),
		RangeProof:     make([]byte, 228), // dummy, won't reach range proof check
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidProof)
}

