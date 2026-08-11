package sdk

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	elgamal "github.com/nixprotocol/elgamal-bn254"
)

func TestDeriveRandomness_Deterministic(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(12345)
	balance := make([]byte, 128)

	r1, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)

	r2, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)

	// Same inputs → same output.
	require.Equal(t, r1, r2, "same inputs must produce same randomness")
}

func TestDeriveRandomness_DifferentInputs(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(12345)
	balance := make([]byte, 128)

	r1, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)

	// Different denom.
	r2, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "test-chain", Denom: "uosmo", Op: OpShield})
	require.NoError(t, err)
	require.NotEqual(t, r1, r2, "different denom must produce different r")

	// Different op type.
	r3, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpUnshield})
	require.NoError(t, err)
	require.NotEqual(t, r1, r3, "different op type must produce different r")

	// Different balance (simulates state change).
	balance2 := make([]byte, 128)
	balance2[0] = 0xFF
	r4, err := DeriveRandomness(&sk, balance2, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)
	require.NotEqual(t, r1, r4, "different balance state must produce different r")

	// Different chain ID.
	r5, err := DeriveRandomness(&sk, balance, DerivationContext{ChainID: "other-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)
	require.NotEqual(t, r1, r5, "different chain must produce different r")

	// Different secret key.
	var sk2 fr.Element
	sk2.SetUint64(99999)
	r6, err := DeriveRandomness(&sk2, balance, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)
	require.NotEqual(t, r1, r6, "different sk must produce different r")
}

func TestDeriveRandomness_NilBalance(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(42)

	// Nil balance (first operation on a new denom) should not error.
	r, err := DeriveRandomness(&sk, nil, DerivationContext{ChainID: "test-chain", Denom: "uatom", Op: OpShield})
	require.NoError(t, err)
	require.False(t, r.IsZero(), "derived r should not be zero")
}

func TestDeriveRandomness_NonZero(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(1)

	// Run many derivations; none should be zero (astronomically unlikely).
	for i := uint32(0); i < 100; i++ {
		r, err := DeriveRandomnessWithIndex(&sk, nil, DerivationContext{ChainID: "chain", Denom: "denom", Op: OpShield}, i)
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
	result, err := client.Shield("cosmos1sender", "uatom", 500, nil, 0)
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
	result2, err := client.Shield("cosmos1sender", "uatom", 500, nil, 0)
	require.NoError(t, err)
	require.Equal(t, result.Ciphertext, result2.Ciphertext)
}

func TestClient_ShieldDifferentBalanceState(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain-1")

	// First shield with nil balance.
	r1, err := client.Shield("cosmos1sender", "uatom", 500, nil, 0)
	require.NoError(t, err)

	// Second shield with different balance state (simulating post-first-shield).
	r2, err := client.Shield("cosmos1sender", "uatom", 500, r1.Ciphertext, 0)
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
	shieldResult, err := alice.Shield(aliceSender, "uatom", 1000, nil, 0)
	require.NoError(t, err)
	aliceState.AfterShield(1000, &shieldResult.R)

	// 2. Alice sends 300 to Bob.
	sendResult, err := alice.Send(
		aliceSender, bobReceiver, "uatom",
		300, aliceState, shieldResult.Ciphertext,
		&bobPk, &auditorPk, 64, 0,
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
		aliceState, newAvailBytes, 64, 1,
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
	shieldResult, err := alice.Shield("cosmos1alice", "uatom", 1000, nil, 0)
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
		0,
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
	// The available balance after ApplyPending is shield + newCt; the send's
	// remaining-balance commitment is bound to (available - senderCt), so the
	// real ciphertext has to be passed here.
	var shieldCtAP elgamal.Ciphertext
	require.NoError(t, shieldCtAP.Unmarshal(shieldResult.Ciphertext))
	availAfterApply := elgamal.Add(&shieldCtAP, &newCt)

	sendResult, err := alice.Send(
		"cosmos1alice", "cosmos1bob", "uatom", 100,
		aliceState, availAfterApply.Marshal(),
		&bobPk, &alicePk, 64, 1,
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
	_, err = client.Send("sender", "receiver", "uatom", 500, state, nil, &receiverPk, &auditorPk, 64, 0)
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
	_, err = client.Send("sender", "receiver", "uatom", 200, state, nil, &receiverPk, &auditorPk, 64, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient balance")
}

func TestClient_UnshieldInsufficientBalance(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(nil)
	require.NoError(t, err)

	client := NewClient(&sk, &pk, "test-chain")
	state := &BalanceState{Value: 100, RandomnessKnown: true}
	_, err = client.Unshield("sender", "uatom", 200, state, nil, 64, 0)
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
	_, err = client.Send("sender", "receiver", "uatom", 50, state, nil, &receiverPk, &auditorPk, 64, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "randomness unknown")
}

// TestDeriveRandomness_NoReuseAcrossRetries covers the leak that content
// binding exists to prevent.
//
// A transaction that is evicted and rebuilt at a different amount keeps the
// same account sequence and the same balance snapshot. If r were derived from
// those alone, both ciphertexts would share r and an observer seeing both in
// the mempool could compute v_A - v_B.
func TestDeriveRandomness_NoReuseAcrossRetries(t *testing.T) {
	var sk fr.Element
	sk.SetUint64(12345)
	balance := []byte("same-snapshot")

	base := DerivationContext{
		ChainID: "test-chain", Denom: "uatom", Op: OpSendSender,
		Sequence: 7, Amount: 300, Receiver: "cosmos1bob",
	}

	must := func(c DerivationContext) fr.Element {
		r, err := DeriveRandomness(&sk, balance, c)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		return r
	}

	r300 := must(base)

	// Same everything -> same r. Determinism is required for state recovery,
	// and an identical context means an identical ciphertext, so there is
	// nothing to compare against and nothing leaks.
	if !r300.Equal(&[]fr.Element{must(base)}[0]) {
		t.Fatal("derivation is not deterministic")
	}

	// Retry at a different amount, same sequence and snapshot.
	retry := base
	retry.Amount = 400
	r400 := must(retry)
	if r300.Equal(&r400) {
		t.Fatal("retry at a different amount reused r: leaks the amount difference")
	}

	// Same amount to a different receiver.
	other := base
	other.Receiver = "cosmos1carol"
	rOther := must(other)
	if r300.Equal(&rOther) {
		t.Fatal("different receiver reused r")
	}

	// Same content resubmitted as a distinct transaction.
	nextSeq := base
	nextSeq.Sequence = 8
	rNext := must(nextSeq)
	if r300.Equal(&rNext) {
		t.Fatal("different sequence reused r")
	}
}

// TestApplyPending_NoRandomnessReuseAcrossIncomingTransfer covers the case the
// send/unshield content binding does not: ApplyPending re-encrypts the PENDING
// total, but its salt is the AVAILABLE balance, which an incoming transfer does
// not move (incoming funds land in pending, and the account sequence is
// unchanged too).
//
// If the pending amount were not bound into the derivation, two ApplyPending
// attempts straddling an incoming transfer would share rNew while encrypting
// different values, and an observer could subtract the two ciphertexts to
// recover the incoming amount without any secret key.
func TestApplyPending_NoRandomnessReuseAcrossIncomingTransfer(t *testing.T) {
	sk, pk, err := elgamal.KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(&sk, &pk, "test-chain")
	table := elgamal.NewDecryptionTable(16)

	// Available balance is the salt; it stays fixed across both attempts.
	var availR fr.Element
	if _, err := availR.SetRandom(); err != nil {
		t.Fatal(err)
	}
	availCt, _, err := elgamal.EncryptWithRandomness(500, &pk, &availR)
	if err != nil {
		t.Fatal(err)
	}
	availBytes := availCt.Marshal()

	applyWithPending := func(pending uint64) *ApplyPendingResult {
		var r fr.Element
		if _, err := r.SetRandom(); err != nil {
			t.Fatal(err)
		}
		pendCt, _, err := elgamal.EncryptWithRandomness(pending, &pk, &r)
		if err != nil {
			t.Fatal(err)
		}
		// Same sequence for both: a retry reuses the account sequence.
		res, err := client.ApplyPending("cosmos1alice", "uatom", availBytes, pendCt.Marshal(), table, 3)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	first := applyWithPending(1000)
	second := applyWithPending(1250) // an incoming 250 landed in pending

	if first.RNew.Equal(&second.RNew) {
		t.Fatal("rNew reused across an incoming transfer: ciphertext difference leaks the incoming amount")
	}

	// Concretely: with reuse, newCt2.C2 - newCt1.C2 = (P2-P1)*G, solvable by
	// anyone. Confirm that subtraction no longer yields a small-DLOG point.
	var ct1, ct2 elgamal.Ciphertext
	if err := ct1.Unmarshal(first.NewAvailableUpdate); err != nil {
		t.Fatal(err)
	}
	if err := ct2.Unmarshal(second.NewAvailableUpdate); err != nil {
		t.Fatal(err)
	}
	diff := elgamal.Sub(&ct2, &ct1)
	if _, err := table.DiscreteLog(&diff.C2); err == nil {
		t.Fatal("observer recovered the plaintext difference from the ciphertexts")
	}

	// Determinism is still intact: same pending, same sequence -> same rNew.
	if !applyWithPending(1000).RNew.Equal(&first.RNew) {
		t.Fatal("derivation is no longer deterministic for identical inputs")
	}
}
