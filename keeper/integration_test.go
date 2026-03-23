package keeper_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"testing"

	"cosmossdk.io/core/store"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
)

// ---------------------------------------------------------------------------
// Mock BankKeeper
// ---------------------------------------------------------------------------

type mockBankKeeper struct {
	balances map[string]map[string]sdkmath.Int // addr -> denom -> amount
}

func newMockBankKeeper() *mockBankKeeper {
	return &mockBankKeeper{balances: make(map[string]map[string]sdkmath.Int)}
}

func (m *mockBankKeeper) fundAccount(addr string, denom string, amount int64) {
	if m.balances[addr] == nil {
		m.balances[addr] = make(map[string]sdkmath.Int)
	}
	m.balances[addr][denom] = sdkmath.NewInt(amount)
}

func (m *mockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, senderAddr sdk.AccAddress, _ string, amt sdk.Coins) error {
	addr := senderAddr.String()
	for _, coin := range amt {
		bal, ok := m.balances[addr][coin.Denom]
		if !ok || bal.LT(coin.Amount) {
			return fmt.Errorf("insufficient funds")
		}
		m.balances[addr][coin.Denom] = bal.Sub(coin.Amount)
	}
	return nil
}

func (m *mockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, _ string, recipientAddr sdk.AccAddress, amt sdk.Coins) error {
	addr := recipientAddr.String()
	if m.balances[addr] == nil {
		m.balances[addr] = make(map[string]sdkmath.Int)
	}
	for _, coin := range amt {
		bal, ok := m.balances[addr][coin.Denom]
		if !ok {
			bal = sdkmath.ZeroInt()
		}
		m.balances[addr][coin.Denom] = bal.Add(coin.Amount)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mock address.Codec  (bech32-based, using cosmos-sdk)
// ---------------------------------------------------------------------------

type testAddressCodec struct{}

func (testAddressCodec) StringToBytes(text string) ([]byte, error) {
	addr, err := sdk.AccAddressFromBech32(text)
	if err != nil {
		return nil, err
	}
	return addr.Bytes(), nil
}

func (testAddressCodec) BytesToString(bz []byte) (string, error) {
	return sdk.AccAddress(bz).String(), nil
}

// ---------------------------------------------------------------------------
// In-memory KV store implementations
// ---------------------------------------------------------------------------

// memKVStore is a minimal in-memory KV store implementing store.KVStore.
type memKVStore struct {
	data map[string][]byte
}

func newMemKVStore() *memKVStore {
	return &memKVStore{data: make(map[string][]byte)}
}

func (s *memKVStore) Get(key []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}
	v, ok := s.data[string(key)]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (s *memKVStore) Has(key []byte) (bool, error) {
	if key == nil {
		return false, fmt.Errorf("key is nil")
	}
	_, ok := s.data[string(key)]
	return ok, nil
}

func (s *memKVStore) Set(key, value []byte) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}
	if value == nil {
		return fmt.Errorf("value is nil")
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[string(key)] = cp
	return nil
}

func (s *memKVStore) Delete(key []byte) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}
	delete(s.data, string(key))
	return nil
}

func (s *memKVStore) Iterator(start, end []byte) (store.Iterator, error) {
	return newMemIterator(s.data, start, end, true), nil
}

func (s *memKVStore) ReverseIterator(start, end []byte) (store.Iterator, error) {
	return newMemIterator(s.data, start, end, false), nil
}

// memIterator iterates over sorted keys in a map.
type memIterator struct {
	keys   []string
	values [][]byte
	pos    int
	start  []byte
	end    []byte
}

func newMemIterator(data map[string][]byte, start, end []byte, ascending bool) *memIterator {
	keys := make([]string, 0, len(data))
	for k := range data {
		kb := []byte(k)
		if start != nil && bytes.Compare(kb, start) < 0 {
			continue
		}
		if end != nil && bytes.Compare(kb, end) >= 0 {
			continue
		}
		keys = append(keys, k)
	}
	if ascending {
		sort.Strings(keys)
	} else {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	}

	values := make([][]byte, len(keys))
	for i, k := range keys {
		v := data[k]
		cp := make([]byte, len(v))
		copy(cp, v)
		values[i] = cp
	}

	return &memIterator{keys: keys, values: values, pos: 0, start: start, end: end}
}

func (it *memIterator) Domain() ([]byte, []byte) { return it.start, it.end }
func (it *memIterator) Valid() bool               { return it.pos < len(it.keys) }
func (it *memIterator) Next()                     { it.pos++ }
func (it *memIterator) Key() []byte               { return []byte(it.keys[it.pos]) }
func (it *memIterator) Value() []byte             { return it.values[it.pos] }
func (it *memIterator) Error() error              { return nil }
func (it *memIterator) Close() error              { return nil }

// memStoreService wraps a memKVStore and implements store.KVStoreService.
type memStoreService struct {
	kvStore *memKVStore
}

func (s *memStoreService) OpenKVStore(_ context.Context) store.KVStore {
	return s.kvStore
}

// ---------------------------------------------------------------------------
// Test setup helper
// ---------------------------------------------------------------------------

func setupTestKeeper(t *testing.T) (keeper.Keeper, *mockBankKeeper, sdk.Context) {
	t.Helper()

	storeService := &memStoreService{kvStore: newMemKVStore()}
	bankKeeper := newMockBankKeeper()
	addrCodec := testAddressCodec{}

	// Authority address (20 bytes to produce valid bech32).
	authority := sdk.AccAddress([]byte("authority___________"))

	k := keeper.NewKeeper(storeService, nil, addrCodec, authority, bankKeeper)

	// Minimal sdk.Context with an event manager and chain ID.
	ctx := sdk.Context{}.
		WithContext(context.Background()).
		WithChainID("test-chain-1").
		WithEventManager(sdk.NewEventManager())

	return k, bankKeeper, ctx
}

// ---------------------------------------------------------------------------
// TestFullConfidentialFlow
// ---------------------------------------------------------------------------

func TestFullConfidentialFlow(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	// -- Key generation -------------------------------------------------------
	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// -- Set params (auditor key + enabled denoms) ----------------------------
	params := types.Params{
		AuditorPubKey:         elgamal.MarshalPublicKey(&auditorPk),
		EnabledDenoms:         []string{"uatom"},
		MaxTransferBits:       40,
		AuditorKeyGracePeriod: 100,
		RotationCooldown:      100,
	}
	require.NoError(t, k.SetParams(ctx, params))

	// -- Addresses (20 bytes each for valid bech32) ---------------------------
	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice := aliceAddr.String()
	bob := bobAddr.String()

	// Fund Alice's bank account.
	bankKeeper.fundAccount(alice, "uatom", 10000)

	// =========================================================================
	// Step 1: Register Alice's key
	// =========================================================================
	t.Log("Step 1: Register Alice")
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender:  alice,
		Pubkey:  elgamal.MarshalPublicKey(&alicePk),
		Counter: 0,
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 2: Register Bob's key
	// =========================================================================
	t.Log("Step 2: Register Bob")
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender:  bob,
		Pubkey:  elgamal.MarshalPublicKey(&bobPk),
		Counter: 0,
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 3: Alice shields 1000 uatom
	// =========================================================================
	t.Log("Step 3: Alice shields 1000 uatom")
	shieldAmount := uint64(1000)
	var shieldR fr.Element
	_, err = shieldR.SetRandom()
	require.NoError(t, err)

	shieldCt, _, err := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	require.NoError(t, err)
	shieldCtBytes, err := shieldCt.Marshal()
	require.NoError(t, err)

	// DLEQ proof for shield.
	shieldTranscript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	shieldProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &shieldCt, shieldAmount, shieldTranscript)
	require.NoError(t, err)
	shieldProofBytes := shieldProof.Marshal()

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "1000",
		Ciphertext: shieldCtBytes,
		Proof:      shieldProofBytes,
	})
	require.NoError(t, err)

	// Verify Alice's bank balance decreased.
	require.Equal(t, sdkmath.NewInt(9000), bankKeeper.balances[alice]["uatom"])

	// =========================================================================
	// Step 4: Alice sends 300 to Bob (confidential transfer)
	// =========================================================================
	t.Log("Step 4: Alice sends 300 uatom to Bob")
	sendAmount := uint64(300)
	var rSender, rReceiver, rAuditor fr.Element
	_, err = rSender.SetRandom()
	require.NoError(t, err)
	_, err = rReceiver.SetRandom()
	require.NoError(t, err)
	_, err = rAuditor.SetRandom()
	require.NoError(t, err)

	senderCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rSender)
	require.NoError(t, err)
	receiverCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rReceiver)
	require.NoError(t, err)
	auditorCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &auditorPk, &rAuditor)
	require.NoError(t, err)

	senderCtBytes, err := senderCt.Marshal()
	require.NoError(t, err)
	receiverCtBytes, err := receiverCt.Marshal()
	require.NoError(t, err)
	auditorCtBytes, err := auditorCt.Marshal()
	require.NoError(t, err)

	// Equality proof: all three ciphertexts encrypt the same amount.
	eqTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	equalityProof, err := elgamal.ProveEquality(
		sendAmount,
		&rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk,
		&senderCt, &receiverCt, &auditorCt,
		eqTranscript,
	)
	require.NoError(t, err)
	equalityProofBytes := equalityProof.Marshal()

	// Aggregate range proof for the send:
	//   Commitment 0 (transfer amount):  senderCt.C2 = sendAmount*G + rSender*alicePk
	//   Commitment 1 (remaining balance): (avail - senderCt).C2
	//
	// The range proof prover needs to know the blinding factors. The on-chain
	// available balance includes randomness from RegisterKey's Enc(0, pk, r_init)
	// which the client does not have. In a production system, a client would
	// use RegisterKey with client-supplied randomness, or do an initial
	// ApplyPending to reclaim the balance with known randomness.
	//
	// For this test we overwrite Alice's available balance to a ciphertext
	// with known randomness (shieldR), so we can produce valid range proofs.
	knownAvailCt, _, err := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	require.NoError(t, err)
	knownAvailCtBytes, err := knownAvailCt.Marshal()
	require.NoError(t, err)
	err = k.SetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom", knownAvailCtBytes)
	require.NoError(t, err)

	// Now Alice's available balance blinding is exactly shieldR.
	// After subtracting senderCt (blinding = rSender):
	//   new balance value = 1000 - 300 = 700
	//   new balance blinding = shieldR - rSender
	newBalAmount := shieldAmount - sendAmount // 700
	var newBalR fr.Element
	newBalR.Sub(&shieldR, &rSender)

	// The range proof commitments are C2 of senderCt and C2 of (avail - senderCt).
	// senderCt.C2 has value=300, blinding=rSender.
	// newBal.C2 has value=700, blinding=shieldR - rSender.
	rangeTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{sendAmount, newBalAmount},
		[]*fr.Element{&rSender, &newBalR},
		&alicePk, 40, rangeTranscript,
	)
	require.NoError(t, err)
	aggProofBytes, err := aggProof.Marshal()
	require.NoError(t, err)

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:       senderCtBytes,
		ReceiverUpdate:     receiverCtBytes,
		AuditorUpdate:      auditorCtBytes,
		RangeProof:         aggProofBytes,
		EqualityProof:      equalityProofBytes,
		ReceiverKeyCounter: 0,
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 5: Bob applies pending balance
	// =========================================================================
	t.Log("Step 5: Bob applies pending balance")

	// Read Bob's pending balance from chain.
	bobPendingBytes, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.NotNil(t, bobPendingBytes)

	var bobPendingCt elgamal.Ciphertext
	err = bobPendingCt.Unmarshal(bobPendingBytes)
	require.NoError(t, err)

	// Bob decrypts his pending balance. In the test we know the pending
	// balance is the initial zero (created server-side during RegisterKey)
	// plus the receiverUpdate (Enc(300, bobPk, rReceiver)).
	// Bob can decrypt using his secret key to learn it's 300.
	// For the test we'll use the known value.
	pendingPlaintext := sendAmount // 300

	// Bob creates a fresh re-encryption of the pending plaintext.
	var applyR fr.Element
	_, err = applyR.SetRandom()
	require.NoError(t, err)
	newAvailCt, _, err := elgamal.EncryptWithRandomness(pendingPlaintext, &bobPk, &applyR)
	require.NoError(t, err)
	newAvailCtBytes, err := newAvailCt.Marshal()
	require.NoError(t, err)

	// Prove ApplyPending: pending and newAvailCt encrypt the same amount.
	applyTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	applyProof, err := elgamal.ProveApplyPending(
		&bobSk, &bobPk,
		&bobPendingCt, &newAvailCt,
		pendingPlaintext, &applyR,
		applyTranscript,
	)
	require.NoError(t, err)
	applyProofBytes := applyProof.Marshal()

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             bob,
		Denom:              "uatom",
		NewAvailableUpdate: newAvailCtBytes,
		Proof:              applyProofBytes,
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 6: Bob unshields 300 uatom
	// =========================================================================
	t.Log("Step 6: Bob unshields 300 uatom")

	// Same as Alice's case: overwrite Bob's available balance with a known
	// ciphertext so we can produce valid range proofs for unshield.
	knownBobAvailCt, _, err := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &applyR)
	require.NoError(t, err)
	knownBobAvailCtBytes, err := knownBobAvailCt.Marshal()
	require.NoError(t, err)
	err = k.SetAvailableBalance(ctx, bobAddr.Bytes(), "uatom", knownBobAvailCtBytes)
	require.NoError(t, err)

	// Bob wants to unshield 300 (his entire available balance).
	unshieldAmount := sendAmount // 300
	var unshieldR fr.Element
	_, err = unshieldR.SetRandom()
	require.NoError(t, err)
	unshieldCt, _, err := elgamal.EncryptWithRandomness(unshieldAmount, &bobPk, &unshieldR)
	require.NoError(t, err)
	unshieldCtBytes, err := unshieldCt.Marshal()
	require.NoError(t, err)

	// DLEQ proof: proves the unshield ciphertext encrypts the claimed amount.
	unshieldTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldDLEQ, err := elgamal.ProveDLEQ(&bobSk, &bobPk, &unshieldCt, unshieldAmount, unshieldTranscript)
	require.NoError(t, err)
	unshieldDLEQBytes := unshieldDLEQ.Marshal()

	// Range proof: remaining balance after unshield >= 0.
	// remaining = avail - unshieldCt = Enc(300, bobPk, applyR) - Enc(300, bobPk, unshieldR)
	//           = Enc(0, bobPk, applyR - unshieldR)
	remainAmount := uint64(0)
	var remainR fr.Element
	remainR.Sub(&applyR, &unshieldR)

	// The verifier uses AggregateRangeVerify with a single commitment.
	// The commitment is (avail - unshieldCt).C2 = remainAmount*G + remainR*bobPk
	// which is a Pedersen commitment with value=0, blinding=remainR, base H=bobPk.
	unshieldRangeTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldRangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{remainAmount},
		[]*fr.Element{&remainR},
		&bobPk, 40, unshieldRangeTranscript,
	)
	require.NoError(t, err)
	unshieldRangeProofBytes, err := unshieldRangeProof.Marshal()
	require.NoError(t, err)

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          bob,
		Denom:           "uatom",
		Amount:          "300",
		Ciphertext:      unshieldCtBytes,
		RangeProof:      unshieldRangeProofBytes,
		DecryptionProof: unshieldDLEQBytes,
	})
	require.NoError(t, err)

	// =========================================================================
	// Final assertions
	// =========================================================================
	require.Equal(t, sdkmath.NewInt(300), bankKeeper.balances[bob]["uatom"],
		"Bob should have received 300 uatom in the bank")
	require.Equal(t, sdkmath.NewInt(9000), bankKeeper.balances[alice]["uatom"],
		"Alice's bank balance should remain 9000 (only shielded 1000)")

	t.Log("Full confidential flow completed: register -> shield -> send -> apply pending -> unshield")
}
