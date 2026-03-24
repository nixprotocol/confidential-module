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

// defaultParams returns test params with auditor key set and "uatom" enabled.
func defaultParams(auditorPk []byte) types.Params {
	return types.Params{
		AuditorPubKey:         auditorPk,
		EnabledDenoms:         []string{"uatom"},
		MaxTransferBits:       64,
		AuditorKeyGracePeriod: 100,
		RotationCooldown:      100,
	}
}

// registerAccount is a convenience that registers a valid key for addr with the
// given public key. It assumes params (with auditor + enabled denoms) are already set.
func registerAccount(t *testing.T, msgServer types.MsgServer, ctx sdk.Context, addr string, pk []byte) {
	t.Helper()
	_, err := msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender:  addr,
		Pubkey:  pk,
		Counter: 0,
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
) {
	t.Helper()

	var r fr.Element
	_, err := r.SetRandom()
	require.NoError(t, err)

	ct, _, err := elgamal.EncryptWithRandomness(amount, &pk, &r)
	require.NoError(t, err)
	ctBytes, err := ct.Marshal()
	require.NoError(t, err)

	transcript := k.BuildTranscriptForTest(ctx, addr, "", "uatom")
	proof, err := elgamal.ProveDLEQ(&sk, &pk, &ct, amount, transcript)
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
		Sender:  alice,
		Pubkey:  make([]byte, 32),
		Counter: 0,
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
		Sender:  alice,
		Pubkey:  make([]byte, 64),
		Counter: 0,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidPubkey)
}

func TestRegisterKey_AlreadyRegistered(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	pkBytes := elgamal.MarshalPublicKey(&alicePk)

	// First registration succeeds.
	registerAccount(t, msgServer, ctx, alice, pkBytes)

	// Second registration should fail.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender:  alice,
		Pubkey:  pkBytes,
		Counter: 0,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyAlreadyRegistered)
}

func TestRegisterKey_NonZeroCounter(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()

	// Counter=1 on first registration should fail.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender:  alice,
		Pubkey:  elgamal.MarshalPublicKey(&alicePk),
		Counter: 1,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidCounter)
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

func TestShield_NoAuditorKey(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// Set params with empty auditor key.
	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   nil,
		EnabledDenoms:   []string{"uatom"},
		MaxTransferBits: 64,
	}))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "1000",
		Ciphertext: make([]byte, 128),
		Proof:      make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrAuditorKeyNotSet)
}

func TestShield_DenomNotEnabled(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	// Use a denom that is not in enabled_denoms ("uosmo" is not enabled).
	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uosmo",
		Amount:     "1000",
		Ciphertext: make([]byte, 128),
		Proof:      make([]byte, elgamal.DLEQProofSize),
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrDenomNotEnabled)
}

func TestShield_ZeroAmount(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

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
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	// Create a valid ciphertext for amount=1000, but generate proof with wrong amount=500.
	var r fr.Element
	_, err = r.SetRandom()
	require.NoError(t, err)

	ct, _, err := elgamal.EncryptWithRandomness(1000, &alicePk, &r)
	require.NoError(t, err)
	ctBytes, err := ct.Marshal()
	require.NoError(t, err)

	// Prove with wrong amount (500 instead of 1000).
	transcript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	wrongProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &ct, 500, transcript)
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
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	// Shield first so Alice has balance.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Bob is NOT registered. Send to Bob should fail.
	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:       make([]byte, 128),
		ReceiverUpdate:     make([]byte, 128),
		AuditorUpdate:      make([]byte, 128),
		RangeProof:         make([]byte, 100),
		EqualityProof:      make([]byte, elgamal.EqualityProofSize),
		ReceiverKeyCounter: 0,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrKeyNotRegistered)
}

func TestSend_ReceiverKeyRotated(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bob := sdk.AccAddress([]byte("bob_________________")).String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))
	registerAccount(t, msgServer, ctx, bob, elgamal.MarshalPublicKey(&bobPk))

	// Shield so Alice has balance.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Send with wrong receiver key counter (5 instead of 0).
	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:       make([]byte, 128),
		ReceiverUpdate:     make([]byte, 128),
		AuditorUpdate:      make([]byte, 128),
		RangeProof:         make([]byte, 100),
		EqualityProof:      make([]byte, elgamal.EqualityProofSize),
		ReceiverKeyCounter: 5,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrReceiverKeyRotated)
}

func TestSend_InvalidEqualityProof(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bob := sdk.AccAddress([]byte("bob_________________")).String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))
	registerAccount(t, msgServer, ctx, bob, elgamal.MarshalPublicKey(&bobPk))

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

	senderCtBytes, _ := senderCt.Marshal()
	receiverCtBytes, _ := receiverCt.Marshal()
	auditorCtBytes, _ := auditorCt.Marshal()

	// Generate a valid equality proof then tamper with it.
	eqTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	eqProof, err := elgamal.ProveEquality(
		sendAmount,
		&rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk,
		&senderCt, &receiverCt, &auditorCt,
		eqTranscript,
	)
	require.NoError(t, err)
	proofBytes := eqProof.Marshal()

	// Tamper: flip a byte in the middle of the proof.
	proofBytes[len(proofBytes)/2] ^= 0xFF

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:       senderCtBytes,
		ReceiverUpdate:     receiverCtBytes,
		AuditorUpdate:      auditorCtBytes,
		RangeProof:         make([]byte, 100), // will not reach range proof verification
		EqualityProof:      proofBytes,
		ReceiverKeyCounter: 0,
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

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

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
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	// Shield 100.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 100)

	// Try to unshield 500 (more than available). Use a random DLEQ proof for 500 —
	// the DLEQ or range proof verification should fail.
	var r fr.Element
	_, _ = r.SetRandom()
	ct, _, err := elgamal.EncryptWithRandomness(500, &alicePk, &r)
	require.NoError(t, err)
	ctBytes, err := ct.Marshal()
	require.NoError(t, err)

	// Generate DLEQ proof for amount=500 (this is a valid DLEQ, but the range
	// proof for remaining balance = -400 cannot be valid).
	transcript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	dleqProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &ct, 500, transcript)
	require.NoError(t, err)
	dleqBytes := dleqProof.Marshal()

	// Provide a garbage range proof — range proof verification will fail.
	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          alice,
		Denom:           "uatom",
		Amount:          "500",
		Ciphertext:      ctBytes,
		RangeProof:      make([]byte, 100),
		DecryptionProof: dleqBytes,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidProof)
}

func TestUnshield_ZeroAmount(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

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
	require.ErrorIs(t, err, types.ErrAuditorKeyNotSet)
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
	require.ErrorIs(t, err, types.ErrAuditorKeyNotSet)
}

// ===========================================================================
// MsgRotateKey errors
// ===========================================================================

func TestRotateKey_WrongCounter(t *testing.T) {
	k, _, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	_, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, newPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	alice := sdk.AccAddress([]byte("alice_______________")).String()
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))

	// Try to rotate with counter=5 when current=0 (expected=1).
	_, err = msgServer.RotateKey(ctx, &types.MsgRotateKey{
		Sender:     alice,
		NewPubkey:  elgamal.MarshalPublicKey(&newPk),
		NewCounter: 5,
		ReEncryptedAvailable: []*types.DenomCiphertext{
			{Denom: "uatom", Ciphertext: make([]byte, 128)},
		},
		EqualityProofs: []*types.DenomProof{
			{Denom: "uatom", Proof: make([]byte, 100)},
		},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidCounter)
}

func TestRotateKey_PendingNotZero(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, defaultParams(elgamal.MarshalPublicKey(&auditorPk))))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	alice := aliceAddr.String()
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	bob := bobAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 10000)
	registerAccount(t, msgServer, ctx, alice, elgamal.MarshalPublicKey(&alicePk))
	registerAccount(t, msgServer, ctx, bob, elgamal.MarshalPublicKey(&bobPk))

	// Shield so Alice has balance.
	shieldAccount(t, k, msgServer, ctx, aliceSk, alicePk, alice, 1000)

	// Manually set Bob's pending-is-zero flag to false to simulate incoming funds.
	require.NoError(t, k.SetPendingIsZero(ctx, bobAddr.Bytes(), "uatom", false))

	// Bob tries to rotate without applying pending.
	_, newPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	_, err = msgServer.RotateKey(ctx, &types.MsgRotateKey{
		Sender:     bob,
		NewPubkey:  elgamal.MarshalPublicKey(&newPk),
		NewCounter: 1,
		ReEncryptedAvailable: []*types.DenomCiphertext{
			{Denom: "uatom", Ciphertext: make([]byte, 128)},
		},
		EqualityProofs: []*types.DenomProof{
			{Denom: "uatom", Proof: make([]byte, 100)},
		},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrPendingNotZero)
}
