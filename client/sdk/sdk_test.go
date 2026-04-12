package sdk

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

func TestDeriveRandomness_Deterministic(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(12345)
	balance := make([]byte, 128)

	r1, err := DeriveRandomness(&sk, "test-chain", "uatom", balance, OpShield)
	require.NoError(t, err)

	r2, err := DeriveRandomness(&sk, "test-chain", "uatom", balance, OpShield)
	require.NoError(t, err)

	// Same inputs → same output.
	require.Equal(t, r1, r2, "same inputs must produce same randomness")
}

func TestDeriveRandomness_DifferentInputs(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(12345)
	balance := make([]byte, 128)

	r1, err := DeriveRandomness(&sk, "test-chain", "uatom", balance, OpShield)
	require.NoError(t, err)

	// Different denom.
	r2, err := DeriveRandomness(&sk, "test-chain", "uosmo", balance, OpShield)
	require.NoError(t, err)
	require.NotEqual(t, r1, r2, "different denom must produce different r")

	// Different op type.
	r3, err := DeriveRandomness(&sk, "test-chain", "uatom", balance, OpUnshield)
	require.NoError(t, err)
	require.NotEqual(t, r1, r3, "different op type must produce different r")

	// Different balance (simulates state change).
	balance2 := make([]byte, 128)
	balance2[0] = 0xFF
	r4, err := DeriveRandomness(&sk, "test-chain", "uatom", balance2, OpShield)
	require.NoError(t, err)
	require.NotEqual(t, r1, r4, "different balance state must produce different r")

	// Different chain ID.
	r5, err := DeriveRandomness(&sk, "other-chain", "uatom", balance, OpShield)
	require.NoError(t, err)
	require.NotEqual(t, r1, r5, "different chain must produce different r")

	// Different secret key.
	var sk2 fr.Element
	sk2.SetUint64(99999)
	r6, err := DeriveRandomness(&sk2, "test-chain", "uatom", balance, OpShield)
	require.NoError(t, err)
	require.NotEqual(t, r1, r6, "different sk must produce different r")
}

func TestDeriveRandomness_NilBalance(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(42)

	// Nil balance (first operation on a new denom) should not error.
	r, err := DeriveRandomness(&sk, "test-chain", "uatom", nil, OpShield)
	require.NoError(t, err)
	require.False(t, r.IsZero(), "derived r should not be zero")
}

func TestDeriveRandomness_NonZero(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(1)

	// Run many derivations; none should be zero (astronomically unlikely).
	for i := uint32(0); i < 100; i++ {
		r, err := DeriveRandomnessWithIndex(&sk, "chain", "denom", nil, OpShield, i)
		require.NoError(t, err)
		require.False(t, r.IsZero(), "r at index %d should not be zero", i)
	}
}

func TestClient_ShieldAndVerify(t *testing.T) {
	// Generate keys.
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain-1")
	require.Equal(t, 64, len(client.PublicKey()))

	// Shield 500 uatom with no prior balance.
	result, err := client.Shield("cosmos1sender", "uatom", 500, nil)
	require.NoError(t, err)
	require.Len(t, result.Ciphertext, 128)
	require.NotEmpty(t, result.Proof)

	// Verify the ciphertext decrypts to 500.
	var ct elgamal.Ciphertext
	require.NoError(t, ct.Unmarshal(result.Ciphertext))

	table := elgamal.NewDecryptionTable(16)
	decrypted, err := elgamal.Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(500), decrypted)

	// Verify determinism: same inputs → same ciphertext.
	result2, err := client.Shield("cosmos1sender", "uatom", 500, nil)
	require.NoError(t, err)
	require.Equal(t, result.Ciphertext, result2.Ciphertext)
}

func TestClient_ShieldDifferentBalanceState(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain-1")

	// First shield with nil balance.
	r1, err := client.Shield("cosmos1sender", "uatom", 500, nil)
	require.NoError(t, err)

	// Second shield with different balance state (simulating post-first-shield).
	r2, err := client.Shield("cosmos1sender", "uatom", 500, r1.Ciphertext)
	require.NoError(t, err)

	// Different balance state → different ciphertext (even for same amount).
	require.NotEqual(t, r1.Ciphertext, r2.Ciphertext)
}

func TestBalanceState_Tracking(t *testing.T) {
	state := &BalanceState{}

	// Shield 1000.
	var r1 fr.Element
	r1.SetUint64(42)
	state.AfterShield(1000, &r1)
	require.Equal(t, uint64(1000), state.Value)

	// Send 300.
	var r2 fr.Element
	r2.SetUint64(7)
	state.AfterSend(300, &r2)
	require.Equal(t, uint64(700), state.Value)

	// Apply pending of 200.
	var r3 fr.Element
	r3.SetUint64(99)
	state.AfterApplyPending(200, &r3)
	require.Equal(t, uint64(900), state.Value)

	// Unshield 100.
	var r4 fr.Element
	r4.SetUint64(13)
	state.AfterUnshield(100, &r4)
	require.Equal(t, uint64(800), state.Value)

	// Verify cumulative randomness: r1 - r2 + r3 - r4.
	var expected fr.Element
	expected.Add(&r1, &r3)
	var sub fr.Element
	sub.Add(&r2, &r4)
	expected.Sub(&expected, &sub)
	require.Equal(t, expected, state.Randomness)
}

func TestClient_FullFlow(t *testing.T) {
	// Setup: Alice and Bob keys + auditor.
	aliceSk, alicePk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	alice := NewClient(&aliceSk, &alicePk, "test-chain")
	alice.MinSendAmount = 0 // disable for test
	bob := NewClient(&bobSk, &bobPk, "test-chain")
	_ = bob // used later

	aliceState := &BalanceState{}
	aliceSender := "cosmos1alice"
	bobReceiver := "cosmos1bob"

	// 1. Alice shields 1000 uatom.
	shieldResult, err := alice.Shield(aliceSender, "uatom", 1000, nil)
	require.NoError(t, err)
	aliceState.AfterShield(1000, &shieldResult.R)

	// 2. Alice sends 300 to Bob.
	sendResult, err := alice.Send(
		aliceSender, bobReceiver, "uatom",
		300, aliceState, shieldResult.Ciphertext,
		&bobPk, &auditorPk, 64,
	)
	require.NoError(t, err)
	aliceState.AfterSend(300, &sendResult.RSender)
	require.Equal(t, uint64(700), aliceState.Value)

	// 3. Verify Bob can decrypt the receiver update.
	var recvCt elgamal.Ciphertext
	require.NoError(t, recvCt.Unmarshal(sendResult.ReceiverUpdate))
	table := elgamal.NewDecryptionTable(16)
	decrypted, err := elgamal.Decrypt(&recvCt, &bobSk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(300), decrypted)

	// 4. Alice unshields 200.
	// First compute Alice's current available balance after the send.
	var shieldCt elgamal.Ciphertext
	require.NoError(t, shieldCt.Unmarshal(shieldResult.Ciphertext))
	var senderCt elgamal.Ciphertext
	require.NoError(t, senderCt.Unmarshal(sendResult.SenderUpdate))
	newAvailCt := elgamal.Sub(&shieldCt, &senderCt)
	newAvailBytes := newAvailCt.Marshal()

	unshieldResult, err := alice.Unshield(
		aliceSender, "uatom", 200,
		aliceState, newAvailBytes, 64,
	)
	require.NoError(t, err)
	aliceState.AfterUnshield(200, &unshieldResult.R)
	require.Equal(t, uint64(500), aliceState.Value)

	// Verify the unshield ciphertext decrypts to 200.
	var unshieldCt elgamal.Ciphertext
	require.NoError(t, unshieldCt.Unmarshal(unshieldResult.Ciphertext))
	decrypted, err = elgamal.Decrypt(&unshieldCt, &aliceSk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(200), decrypted)

	t.Logf("Full flow passed: shield(1000) → send(300) → unshield(200) → remaining: %d", aliceState.Value)
}

func TestClient_ApplyPending(t *testing.T) {
	// Setup: Alice and Bob.
	aliceSk, alicePk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	_, bobPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	alice := NewClient(&aliceSk, &alicePk, "test-chain")
	alice.MinSendAmount = 0

	// Simulate: Alice shields 1000, then someone sends 300 to Alice.
	// Alice's available = Enc(1000, alicePk, r_shield)
	// Alice's pending = Enc(300, alicePk, r_incoming)

	// Shield 1000.
	shieldResult, err := alice.Shield("cosmos1alice", "uatom", 1000, nil)
	require.NoError(t, err)
	aliceState := &BalanceState{}
	aliceState.AfterShield(1000, &shieldResult.R)

	// Simulate an incoming send by encrypting 300 under Alice's pk.
	var rIncoming fr.Element
	rIncoming.SetUint64(777)
	pendingCt, _, err := elgamal.EncryptWithRandomness(300, &alicePk, &rIncoming)
	require.NoError(t, err)
	pendingBytes := pendingCt.Marshal()

	// ApplyPending: Alice decrypts pending (300) and re-encrypts with known randomness.
	table := elgamal.NewDecryptionTable(16)
	applyResult, err := alice.ApplyPending(
		"cosmos1alice", "uatom",
		shieldResult.Ciphertext, // currentAvailBalance
		pendingBytes,            // currentPendBalance
		table,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(300), applyResult.DecryptedAmount)
	require.NotEmpty(t, applyResult.NewAvailableUpdate)
	require.NotEmpty(t, applyResult.Proof)

	// Verify the re-encrypted ciphertext decrypts to 300.
	var newCt elgamal.Ciphertext
	require.NoError(t, newCt.Unmarshal(applyResult.NewAvailableUpdate))
	decrypted, err := elgamal.Decrypt(&newCt, &aliceSk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(300), decrypted)

	// Update state.
	aliceState.AfterApplyPending(300, &applyResult.RNew)
	require.Equal(t, uint64(1300), aliceState.Value)
	require.True(t, aliceState.RandomnessKnown)

	// Verify Alice can now send using the updated state (proves randomness is correct).
	sendResult, err := alice.Send(
		"cosmos1alice", "cosmos1bob", "uatom", 100,
		aliceState, nil, // availBalance doesn't matter for proof construction test
		&bobPk, &alicePk, 64,
	)
	require.NoError(t, err)
	require.NotEmpty(t, sendResult.RangeProof)

	t.Log("ApplyPending test passed: shield(1000) + pending(300) → apply → send(100)")
}

func TestClient_SendMinAmount(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain") // MinSendAmount = 1000
	_, auditorPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	_, receiverPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	state := &BalanceState{Value: 10000, RandomnessKnown: true}
	_, err = client.Send("sender", "receiver", "uatom", 500, state, nil, &receiverPk, &auditorPk, 64)
	require.Error(t, err)
	require.Contains(t, err.Error(), "below minimum send amount")
}

func TestClient_SendInsufficientBalance(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain")
	client.MinSendAmount = 0
	_, auditorPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	_, receiverPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	state := &BalanceState{Value: 100, RandomnessKnown: true}
	_, err = client.Send("sender", "receiver", "uatom", 200, state, nil, &receiverPk, &auditorPk, 64)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient balance")
}

func TestClient_UnshieldInsufficientBalance(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain")
	state := &BalanceState{Value: 100, RandomnessKnown: true}
	_, err = client.Unshield("sender", "uatom", 200, state, nil, 64)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient balance")
}

func TestClient_SendUnknownRandomness(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain")
	client.MinSendAmount = 0
	_, auditorPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)
	_, receiverPk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	state := &BalanceState{Value: 100, RandomnessKnown: false}
	_, err = client.Send("sender", "receiver", "uatom", 50, state, nil, &receiverPk, &auditorPk, 64)
	require.Error(t, err)
	require.Contains(t, err.Error(), "randomness unknown")
}
