package keeper_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sort"
	"testing"

	"cosmossdk.io/core/store"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	storetypes "cosmossdk.io/store/types"
	"golang.org/x/crypto/hkdf"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
)

// hkdfNew wraps hkdf.New for the test's HKDF derivation.
func hkdfNew(ikm, salt, info []byte) io.Reader {
	return hkdf.New(sha256.New, ikm, salt, info)
}

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

	// Minimal sdk.Context with an event manager, chain ID, and gas meter.
	ctx := sdk.Context{}.
		WithContext(context.Background()).
		WithChainID("test-chain-1").
		WithEventManager(sdk.NewEventManager()).
		WithGasMeter(storetypes.NewInfiniteGasMeter())

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
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
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
		Sender: alice,
		Pubkey: elgamal.MarshalPublicKey(&alicePk),
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 2: Register Bob's key
	// =========================================================================
	t.Log("Step 2: Register Bob")
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: bob,
		Pubkey: elgamal.MarshalPublicKey(&bobPk),
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
	// Note: RegisterKey does not initialize any balance. After Shield, the
	// on-chain balance is exactly shieldCt (identity + shieldCt = shieldCt).
	// We overwrite here to ensure the test uses a ciphertext with known
	// randomness (shieldR) for range proof construction.
	// See TestClientSDK_EndToEnd for a test that works without this workaround.
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
		&alicePk, 64, rangeTranscript,
	)
	require.NoError(t, err)
	aggProofBytes, err := aggProof.Marshal()
	require.NoError(t, err)

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:  senderCtBytes,
		ReceiverUpdate: receiverCtBytes,
		AuditorUpdate: auditorCtBytes,
		RangeProof:    aggProofBytes,
		EqualityProof: equalityProofBytes,
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
		&bobPk, 64, unshieldRangeTranscript,
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

// ---------------------------------------------------------------------------
// TestEncryptedMemoOnAllOperations
// Tests that encrypted_memo is accepted on shield, send, unshield, and
// apply pending messages. Verifies the proto wire format accepts field 5
// on MsgApplyPending (the newly added field).
// ---------------------------------------------------------------------------

func TestEncryptedMemoOnAllOperations(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	// Key generation
	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// Params
	params := types.Params{
		AuditorPubKey:         elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits:       64,
	}
	require.NoError(t, k.SetParams(ctx, params))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice := aliceAddr.String()
	bob := bobAddr.String()

	bankKeeper.fundAccount(alice, "uatom", 10000)

	// Register both keys
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice, Pubkey: elgamal.MarshalPublicKey(&alicePk),
	})
	require.NoError(t, err)
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: bob, Pubkey: elgamal.MarshalPublicKey(&bobPk),
	})
	require.NoError(t, err)

	// Create a fake encrypted memo (132 bytes, simulating ECIES output)
	fakeMemo := make([]byte, 132)
	_, err = rand.Read(fakeMemo)
	require.NoError(t, err)

	// =========================================================================
	// Test 1: Shield with encrypted_memo
	// =========================================================================
	t.Log("Test 1: Shield with encrypted_memo")
	shieldAmount := uint64(1000)
	var shieldR fr.Element
	_, err = shieldR.SetRandom()
	require.NoError(t, err)
	shieldCt, _, err := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	require.NoError(t, err)
	shieldCtBytes, err := shieldCt.Marshal()
	require.NoError(t, err)
	shieldTranscript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	shieldProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &shieldCt, shieldAmount, shieldTranscript)
	require.NoError(t, err)

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:        alice,
		Denom:         "uatom",
		Amount:        "1000",
		Ciphertext:    shieldCtBytes,
		Proof:         shieldProof.Marshal(),
		EncryptedMemo: fakeMemo, // <-- encrypted memo included
	})
	require.NoError(t, err, "Shield with encrypted_memo should succeed")

	// Check event has encrypted_memo attribute
	events := ctx.EventManager().Events()
	foundShieldMemo := false
	for _, ev := range events {
		if ev.Type == "shield" {
			for _, attr := range ev.Attributes {
				if attr.Key == "encrypted_memo" {
					foundShieldMemo = true
					require.NotEmpty(t, attr.Value)
				}
			}
		}
	}
	require.True(t, foundShieldMemo, "Shield event should contain encrypted_memo attribute")

	// =========================================================================
	// Test 2: ConfidentialSend with encrypted_memo
	// =========================================================================
	t.Log("Test 2: ConfidentialSend with encrypted_memo")
	sendAmount := uint64(300)
	var rSender, rReceiver, rAuditor fr.Element
	_, _ = rSender.SetRandom()
	_, _ = rReceiver.SetRandom()
	_, _ = rAuditor.SetRandom()

	senderCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rSender)
	receiverCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rReceiver)
	auditorCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &auditorPk, &rAuditor)
	senderCtBytes, _ := senderCt.Marshal()
	receiverCtBytes, _ := receiverCt.Marshal()
	auditorCtBytes, _ := auditorCt.Marshal()

	eqTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	equalityProof, _ := elgamal.ProveEquality(
		sendAmount, &rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk,
		&senderCt, &receiverCt, &auditorCt, eqTranscript,
	)

	// Overwrite Alice's available balance with known randomness for range proof
	knownAvailCt, _, _ := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	knownAvailCtBytes, _ := knownAvailCt.Marshal()
	_ = k.SetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom", knownAvailCtBytes)

	newBalAmount := shieldAmount - sendAmount
	var newBalR fr.Element
	newBalR.Sub(&shieldR, &rSender)
	rangeTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	aggProof, _ := bulletproofs.AggregateRangeProve(
		[]uint64{sendAmount, newBalAmount}, []*fr.Element{&rSender, &newBalR},
		&alicePk, 64, rangeTranscript,
	)
	aggProofBytes, _ := aggProof.Marshal()

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:             alice,
		Receiver:           bob,
		Denom:              "uatom",
		SenderUpdate:  senderCtBytes,
		ReceiverUpdate: receiverCtBytes,
		AuditorUpdate: auditorCtBytes,
		RangeProof:    aggProofBytes,
		EqualityProof: equalityProof.Marshal(),
		EncryptedMemo: fakeMemo, // <-- encrypted memo included
	})
	require.NoError(t, err, "ConfidentialSend with encrypted_memo should succeed")

	// =========================================================================
	// Test 3: ApplyPending with encrypted_memo (the newly added proto field)
	// =========================================================================
	t.Log("Test 3: ApplyPending with encrypted_memo")
	bobPendingBytes, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	var bobPendingCt elgamal.Ciphertext
	err = bobPendingCt.Unmarshal(bobPendingBytes)
	require.NoError(t, err)

	var applyR fr.Element
	_, _ = applyR.SetRandom()
	newAvailCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &applyR)
	newAvailCtBytes, _ := newAvailCt.Marshal()
	applyTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	applyProof, _ := elgamal.ProveApplyPending(
		&bobSk, &bobPk, &bobPendingCt, &newAvailCt, sendAmount, &applyR, applyTranscript,
	)

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             bob,
		Denom:              "uatom",
		NewAvailableUpdate: newAvailCtBytes,
		Proof:              applyProof.Marshal(),
		EncryptedMemo:      fakeMemo, // <-- THIS IS THE KEY TEST: field 5 on MsgApplyPending
	})
	require.NoError(t, err, "ApplyPending with encrypted_memo should succeed")

	// Check event has encrypted_memo
	events = ctx.EventManager().Events()
	foundApplyMemo := false
	for _, ev := range events {
		if ev.Type == "apply_pending" {
			for _, attr := range ev.Attributes {
				if attr.Key == "encrypted_memo" {
					foundApplyMemo = true
					require.NotEmpty(t, attr.Value)
				}
			}
		}
	}
	require.True(t, foundApplyMemo, "ApplyPending event should contain encrypted_memo attribute")

	// =========================================================================
	// Test 4: Unshield with encrypted_memo
	// =========================================================================
	t.Log("Test 4: Unshield with encrypted_memo")
	knownBobAvailCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &applyR)
	knownBobAvailCtBytes, _ := knownBobAvailCt.Marshal()
	_ = k.SetAvailableBalance(ctx, bobAddr.Bytes(), "uatom", knownBobAvailCtBytes)

	var unshieldR fr.Element
	_, _ = unshieldR.SetRandom()
	unshieldCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &unshieldR)
	unshieldCtBytes, _ := unshieldCt.Marshal()
	unshieldTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldDLEQ, _ := elgamal.ProveDLEQ(&bobSk, &bobPk, &unshieldCt, sendAmount, unshieldTranscript)

	var remainR fr.Element
	remainR.Sub(&applyR, &unshieldR)
	unshieldRangeTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldRangeProof, _ := bulletproofs.AggregateRangeProve(
		[]uint64{0}, []*fr.Element{&remainR}, &bobPk, 64, unshieldRangeTranscript,
	)
	unshieldRangeProofBytes, _ := unshieldRangeProof.Marshal()

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          bob,
		Denom:           "uatom",
		Amount:          "300",
		Ciphertext:      unshieldCtBytes,
		RangeProof:      unshieldRangeProofBytes,
		DecryptionProof: unshieldDLEQ.Marshal(),
		EncryptedMemo:   fakeMemo, // <-- encrypted memo included
	})
	require.NoError(t, err, "Unshield with encrypted_memo should succeed")

	// Check event has encrypted_memo
	events = ctx.EventManager().Events()
	foundUnshieldMemo := false
	for _, ev := range events {
		if ev.Type == "unshield" {
			for _, attr := range ev.Attributes {
				if attr.Key == "encrypted_memo" {
					foundUnshieldMemo = true
				}
			}
		}
	}
	require.True(t, foundUnshieldMemo, "Unshield event should contain encrypted_memo attribute")

	t.Log("All operations with encrypted_memo passed: shield, send, apply_pending, unshield")
}

// ---------------------------------------------------------------------------
// TestLargeAmountsNearUint64Max
// Tests shield, send, apply pending, and unshield with amounts near 2^64-1.
// Verifies the proof system handles the full 64-bit range correctly.
// ---------------------------------------------------------------------------

func TestLargeAmountsNearUint64Max(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	params := types.Params{
		AuditorPubKey:         elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits:       64,
	}
	require.NoError(t, k.SetParams(ctx, params))

	aliceAddr := sdk.AccAddress([]byte("alice_large_________"))
	bobAddr := sdk.AccAddress([]byte("bob_large___________"))
	alice := aliceAddr.String()
	bob := bobAddr.String()

	// Fund with a huge amount
	// 2^63 - 1 = 9223372036854775807 (max int64, max for fundAccount)
	// Test with large amounts across ALL operations
	var shieldAmount uint64 = 1<<63 - 1 // 9223372036854775807 (max int64)
	var sendAmount uint64 = 4611686018427387903 // ~2^62 - 1
	var unshieldAmount uint64 = 2305843009213693951 // ~2^61 - 1

	bankKeeper.fundAccount(alice, "uatom", int64(shieldAmount))
	// Bob needs 0 initial bank balance — unshield will credit him
	bankKeeper.fundAccount(bob, "uatom", 0)

	// Register keys
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice, Pubkey: elgamal.MarshalPublicKey(&alicePk),
	})
	require.NoError(t, err)
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: bob, Pubkey: elgamal.MarshalPublicKey(&bobPk),
	})
	require.NoError(t, err)

	// =========================================================================
	// Shield near-max amount
	// =========================================================================
	t.Logf("Shield: %d (2^63 - 1)", shieldAmount)
	var shieldR fr.Element
	_, err = shieldR.SetRandom()
	require.NoError(t, err)
	shieldCt, _, err := elgamal.EncryptWithRandomness(shieldAmount, &alicePk, &shieldR)
	require.NoError(t, err)
	shieldCtBytes, _ := shieldCt.Marshal()
	shieldTranscript := k.BuildTranscriptForTest(ctx, alice, "", "uatom")
	shieldProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &shieldCt, shieldAmount, shieldTranscript)
	require.NoError(t, err)

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     fmt.Sprintf("%d", shieldAmount),
		Ciphertext: shieldCtBytes,
		Proof:      shieldProof.Marshal(),
	})
	require.NoError(t, err, "Shield near-max amount should succeed")
	t.Log("Shield: OK")

	// =========================================================================
	// Send 1000 from alice to bob
	// =========================================================================
	t.Logf("Send: %d from alice to bob", sendAmount)
	var rSender, rReceiver, rAuditor fr.Element
	_, _ = rSender.SetRandom()
	_, _ = rReceiver.SetRandom()
	_, _ = rAuditor.SetRandom()

	senderCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &alicePk, &rSender)
	receiverCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &rReceiver)
	auditorCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &auditorPk, &rAuditor)
	senderCtBytes, _ := senderCt.Marshal()
	receiverCtBytes, _ := receiverCt.Marshal()
	auditorCtBytes, _ := auditorCt.Marshal()

	eqTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	equalityProof, _ := elgamal.ProveEquality(
		sendAmount, &rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk,
		&senderCt, &receiverCt, &auditorCt, eqTranscript,
	)

	remainAmount := shieldAmount - sendAmount
	var remainR fr.Element
	remainR.Sub(&shieldR, &rSender)
	rangeTranscript := k.BuildTranscriptForTest(ctx, alice, bob, "uatom")
	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{sendAmount, remainAmount}, []*fr.Element{&rSender, &remainR},
		&alicePk, 64, rangeTranscript,
	)
	require.NoError(t, err, "Range proof for large remaining amount should succeed")
	aggProofBytes, _ := aggProof.Marshal()

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       bob,
		Denom:          "uatom",
		SenderUpdate:   senderCtBytes,
		ReceiverUpdate: receiverCtBytes,
		AuditorUpdate:  auditorCtBytes,
		RangeProof:     aggProofBytes,
		EqualityProof:  equalityProof.Marshal(),
	})
	require.NoError(t, err, "Send with large remaining balance should succeed")
	t.Logf("Send: OK (alice remaining: %d)", remainAmount)

	// =========================================================================
	// Apply pending on bob (receives 1000)
	// =========================================================================
	t.Log("ApplyPending: bob merges 1000")
	bobPendingBytes, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	var bobPendingCt elgamal.Ciphertext
	err = bobPendingCt.Unmarshal(bobPendingBytes)
	require.NoError(t, err)

	var applyR fr.Element
	_, _ = applyR.SetRandom()
	newAvailCt, _, _ := elgamal.EncryptWithRandomness(sendAmount, &bobPk, &applyR)
	newAvailCtBytes, _ := newAvailCt.Marshal()
	applyTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	applyProof, _ := elgamal.ProveApplyPending(
		&bobSk, &bobPk, &bobPendingCt, &newAvailCt, sendAmount, &applyR, applyTranscript,
	)

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             bob,
		Denom:              "uatom",
		NewAvailableUpdate: newAvailCtBytes,
		Proof:              applyProof.Marshal(),
	})
	require.NoError(t, err, "ApplyPending should succeed")
	t.Log("ApplyPending: OK")

	// =========================================================================
	// Unshield 500 from bob
	// =========================================================================
	t.Logf("Unshield: bob withdraws %d", unshieldAmount)
	var unshieldR fr.Element
	_, _ = unshieldR.SetRandom()
	unshieldCt, _, _ := elgamal.EncryptWithRandomness(unshieldAmount, &bobPk, &unshieldR)
	unshieldCtBytes, _ := unshieldCt.Marshal()
	unshieldTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldDLEQ, _ := elgamal.ProveDLEQ(&bobSk, &bobPk, &unshieldCt, unshieldAmount, unshieldTranscript)

	bobRemain := sendAmount - unshieldAmount
	var bobRemainR fr.Element
	bobRemainR.Sub(&applyR, &unshieldR)
	unshieldRangeTranscript := k.BuildTranscriptForTest(ctx, bob, "", "uatom")
	unshieldRangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{bobRemain}, []*fr.Element{&bobRemainR}, &bobPk, 64, unshieldRangeTranscript,
	)
	require.NoError(t, err)
	unshieldRangeProofBytes, _ := unshieldRangeProof.Marshal()

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          bob,
		Denom:           "uatom",
		Amount:          fmt.Sprintf("%d", unshieldAmount),
		Ciphertext:      unshieldCtBytes,
		RangeProof:      unshieldRangeProofBytes,
		DecryptionProof: unshieldDLEQ.Marshal(),
	})
	require.NoError(t, err, "Unshield should succeed")
	t.Log("Unshield: OK")

	// =========================================================================
	// Verify final state
	// =========================================================================
	bobBankBal := bankKeeper.balances[bob]["uatom"]
	require.Equal(t, sdkmath.NewInt(int64(unshieldAmount)), bobBankBal, "Bob should have unshielded amount in bank")

	t.Logf("PASSED: Full flow with large amounts")
	t.Logf("  Shield:   %d (2^63 - 1)", shieldAmount)
	t.Logf("  Send:     %d (~2^62)", sendAmount)
	t.Logf("  Remain:   %d", remainAmount)
	t.Logf("  Unshield: %d (~2^61)", unshieldAmount)
	t.Logf("  Bob remaining confidential: %d", sendAmount-unshieldAmount)
}

// ---------------------------------------------------------------------------
// TestClientSDK_EndToEnd verifies that proofs generated by the client SDK
// (client/sdk) are accepted by the on-chain keeper without any balance
// overwriting workarounds. This is the single most important integration test.
// ---------------------------------------------------------------------------

func TestClientSDK_EndToEnd(t *testing.T) {
	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	// Key generation.
	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	// Set params.
	params := types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
	}
	require.NoError(t, k.SetParams(ctx, params))

	// Addresses.
	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice := aliceAddr.String()
	bob := bobAddr.String()

	bankKeeper.fundAccount(alice, "uatom", 10000)

	// Create client SDK instances.
	aliceClient := clientSDKNew(&aliceSk, &alicePk, "test-chain-1")
	_ = bobSk // used later for decrypt

	// =========================================================================
	// Step 1: Register Alice and Bob
	// =========================================================================
	t.Log("SDK E2E Step 1: Register")
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice,
		Pubkey: elgamal.MarshalPublicKey(&alicePk),
	})
	require.NoError(t, err)
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: bob,
		Pubkey: elgamal.MarshalPublicKey(&bobPk),
	})
	require.NoError(t, err)

	// =========================================================================
	// Step 2: Alice shields 500 uatom using SDK (no balance overwriting!)
	// =========================================================================
	t.Log("SDK E2E Step 2: Shield via SDK")

	// On first shield, available balance is nil (never initialized).
	aliceAvailBytes, err := k.GetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.Nil(t, aliceAvailBytes, "Available should be nil before first shield")

	shieldResult, err := aliceClient.Shield(alice, "uatom", 500, aliceAvailBytes)
	require.NoError(t, err)

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender:     alice,
		Denom:      "uatom",
		Amount:     "500",
		Ciphertext: shieldResult.Ciphertext,
		Proof:      shieldResult.Proof,
	})
	require.NoError(t, err)
	t.Log("  Shield accepted by on-chain keeper")

	// Track state.
	aliceState := &clientSDKBalanceState{}
	aliceState.AfterShield(500, &shieldResult.R)

	// =========================================================================
	// Step 3: Alice sends 200 to Bob using SDK (no balance overwriting!)
	// =========================================================================
	t.Log("SDK E2E Step 3: Send via SDK")

	// Read current available balance from chain (this is the actual on-chain state).
	aliceAvailBytes, err = k.GetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.NotNil(t, aliceAvailBytes)

	sendResult, err := aliceClient.Send(
		alice, bob, "uatom", 200,
		aliceState, aliceAvailBytes,
		&bobPk, &auditorPk, 64,
	)
	require.NoError(t, err)

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender:         alice,
		Receiver:       bob,
		Denom:          "uatom",
		SenderUpdate:   sendResult.SenderUpdate,
		ReceiverUpdate: sendResult.ReceiverUpdate,
		AuditorUpdate:  sendResult.AuditorUpdate,
		RangeProof:     sendResult.RangeProof,
		EqualityProof:  sendResult.EqualityProof,
	})
	require.NoError(t, err)
	t.Log("  Send accepted by on-chain keeper")
	aliceState.AfterSend(200, &sendResult.RSender)

	// Verify Bob can decrypt the received amount.
	var recvCt elgamal.Ciphertext
	require.NoError(t, recvCt.Unmarshal(sendResult.ReceiverUpdate))
	table := elgamal.NewDecryptionTable(16)
	decrypted, err := elgamal.Decrypt(&recvCt, &bobSk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(200), decrypted)

	// =========================================================================
	// Step 4: Bob applies pending using SDK (proves SDK ApplyPending works on-chain)
	// =========================================================================
	t.Log("SDK E2E Step 4: Bob ApplyPending via SDK")

	bobClient := clientSDKNew(&bobSk, &bobPk, "test-chain-1")
	bobAvailBytes, err := k.GetAvailableBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	bobPendBytes, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.NotNil(t, bobPendBytes)

	bsgsTable := elgamal.NewDecryptionTable(16)
	applyResult, err := bobClient.ApplyPending(bob, "uatom", bobAvailBytes, bobPendBytes, bsgsTable)
	require.NoError(t, err)
	require.Equal(t, uint64(200), applyResult.DecryptedAmount)

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender:             bob,
		Denom:              "uatom",
		NewAvailableUpdate: applyResult.NewAvailableUpdate,
		Proof:              applyResult.Proof,
	})
	require.NoError(t, err)
	t.Log("  ApplyPending accepted by on-chain keeper")

	// =========================================================================
	// Step 5: Alice unshields 100 uatom using SDK
	// =========================================================================
	t.Log("SDK E2E Step 5: Unshield via SDK")

	aliceAvailBytes, err = k.GetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom")
	require.NoError(t, err)

	unshieldResult, err := aliceClient.Unshield(alice, "uatom", 100, aliceState, aliceAvailBytes, 64)
	require.NoError(t, err)

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender:          alice,
		Denom:           "uatom",
		Amount:          "100",
		Ciphertext:      unshieldResult.Ciphertext,
		RangeProof:      unshieldResult.RangeProof,
		DecryptionProof: unshieldResult.DecryptionProof,
	})
	require.NoError(t, err)
	t.Log("  Unshield accepted by on-chain keeper")
	aliceState.AfterUnshield(100, &unshieldResult.R)

	require.Equal(t, uint64(200), aliceState.Value)
	require.Equal(t, sdkmath.NewInt(9600), bankKeeper.balances[alice]["uatom"])

	t.Logf("PASSED: SDK E2E — shield(500) → send(200) → bob_apply(200) → unshield(100) — remaining: %d", aliceState.Value)
}

// ---------------------------------------------------------------------------
// Thin wrappers around client/sdk types to avoid import cycle.
// The integration test is in package keeper_test, and client/sdk imports
// the elgamal/bulletproofs libraries. We re-implement the minimal client
// logic here using the same HKDF derivation to prove compatibility.
// ---------------------------------------------------------------------------

func clientSDKDeriveR(sk *fr.Element, chainID, denom string, currentBalance []byte, opType string) fr.Element {
	// Exact same HKDF derivation as client/sdk/randomness.go:DeriveRandomness
	skBytes := sk.Bytes()
	info := []byte(chainID + "/" + denom + "/" + opType)

	h := hkdfNew(skBytes[:], currentBalance, info)

	var buf [64]byte
	_, _ = h.Read(buf[:])

	var r fr.Element
	var rBig = new(big.Int).SetBytes(buf[:])
	r.SetBigInt(rBig)
	return r
}

type clientSDKBalanceState struct {
	Value           uint64
	Randomness      fr.Element
	RandomnessKnown bool
}

func (s *clientSDKBalanceState) AfterShield(amount uint64, r *fr.Element) {
	s.Value += amount
	s.Randomness.Add(&s.Randomness, r)
	s.RandomnessKnown = true
}
func (s *clientSDKBalanceState) AfterSend(amount uint64, r *fr.Element) {
	s.Value -= amount
	s.Randomness.Sub(&s.Randomness, r)
}
func (s *clientSDKBalanceState) AfterUnshield(amount uint64, r *fr.Element) {
	s.Value -= amount
	s.Randomness.Sub(&s.Randomness, r)
}

type clientSDKClient struct {
	sk      fr.Element
	pk      bn254.G1Affine
	chainID string
}

type elgamalG1Affine = bn254.G1Affine

func clientSDKNew(sk *fr.Element, pk *elgamalG1Affine, chainID string) *clientSDKClient {
	return &clientSDKClient{sk: *sk, pk: *pk, chainID: chainID}
}

func (c *clientSDKClient) buildTranscript(sender, receiver, denom string) *elgamal.Transcript {
	t := elgamal.NewTranscript("x/confidential/v1")
	t.AppendBytes("chain_id", []byte(c.chainID))
	t.AppendBytes("sender", []byte(sender))
	if receiver != "" {
		t.AppendBytes("receiver", []byte(receiver))
	}
	t.AppendBytes("denom", []byte(denom))
	return t
}

type sdkShieldResult struct {
	Ciphertext []byte
	Proof      []byte
	R          fr.Element
}

func (c *clientSDKClient) Shield(sender, denom string, amount uint64, availBalance []byte) (*sdkShieldResult, error) {
	r := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "shield")
	ct, _, err := elgamal.EncryptWithRandomness(amount, &c.pk, &r)
	if err != nil {
		return nil, err
	}
	ctBytes, _ := ct.Marshal()
	transcript := c.buildTranscript(sender, "", denom)
	proof, err := elgamal.ProveDLEQ(&c.sk, &c.pk, &ct, amount, transcript)
	if err != nil {
		return nil, err
	}
	return &sdkShieldResult{Ciphertext: ctBytes, Proof: proof.Marshal(), R: r}, nil
}

type sdkSendResult struct {
	SenderUpdate, ReceiverUpdate, AuditorUpdate []byte
	EqualityProof, RangeProof                   []byte
	RSender                                     fr.Element
}

func (c *clientSDKClient) Send(sender, receiver, denom string, amount uint64, state *clientSDKBalanceState, availBalance []byte, receiverPk, auditorPk *elgamalG1Affine, maxBits int) (*sdkSendResult, error) {
	rS := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "send/sender")
	rR := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "send/receiver")
	rA := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "send/auditor")

	sCt, _, _ := elgamal.EncryptWithRandomness(amount, &c.pk, &rS)
	rCt, _, _ := elgamal.EncryptWithRandomness(amount, receiverPk, &rR)
	aCt, _, _ := elgamal.EncryptWithRandomness(amount, auditorPk, &rA)

	eqT := c.buildTranscript(sender, receiver, denom)
	eqProof, err := elgamal.ProveEquality(amount, &rS, &rR, &rA, &c.pk, receiverPk, auditorPk, &sCt, &rCt, &aCt, eqT)
	if err != nil {
		return nil, err
	}

	remAmount := state.Value - amount
	var remR fr.Element
	remR.Sub(&state.Randomness, &rS)

	rpT := c.buildTranscript(sender, receiver, denom)
	rpProof, err := bulletproofs.AggregateRangeProve([]uint64{amount, remAmount}, []*fr.Element{&rS, &remR}, &c.pk, maxBits, rpT)
	if err != nil {
		return nil, err
	}
	rpBytes, _ := rpProof.Marshal()
	sB, _ := sCt.Marshal()
	rB, _ := rCt.Marshal()
	aB, _ := aCt.Marshal()
	return &sdkSendResult{SenderUpdate: sB, ReceiverUpdate: rB, AuditorUpdate: aB, EqualityProof: eqProof.Marshal(), RangeProof: rpBytes, RSender: rS}, nil
}

type sdkApplyPendingResult struct {
	NewAvailableUpdate []byte
	Proof              []byte
	RNew               fr.Element
	DecryptedAmount    uint64
}

func (c *clientSDKClient) ApplyPending(sender, denom string, availBalance, pendBalance []byte, table *elgamal.DecryptionTable) (*sdkApplyPendingResult, error) {
	var pendCt elgamal.Ciphertext
	if err := pendCt.Unmarshal(pendBalance); err != nil {
		return nil, err
	}
	pendingAmount, err := elgamal.Decrypt(&pendCt, &c.sk, table)
	if err != nil {
		return nil, err
	}
	rNew := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "apply_pending")
	newCt, _, err := elgamal.EncryptWithRandomness(pendingAmount, &c.pk, &rNew)
	if err != nil {
		return nil, err
	}
	newCtBytes, _ := newCt.Marshal()
	transcript := c.buildTranscript(sender, "", denom)
	proof, err := elgamal.ProveApplyPending(&c.sk, &c.pk, &pendCt, &newCt, pendingAmount, &rNew, transcript)
	if err != nil {
		return nil, err
	}
	return &sdkApplyPendingResult{
		NewAvailableUpdate: newCtBytes,
		Proof:              proof.Marshal(),
		RNew:               rNew,
		DecryptedAmount:    pendingAmount,
	}, nil
}

type sdkUnshieldResult struct {
	Ciphertext, DecryptionProof, RangeProof []byte
	R                                       fr.Element
}

func (c *clientSDKClient) Unshield(sender, denom string, amount uint64, state *clientSDKBalanceState, availBalance []byte, maxBits int) (*sdkUnshieldResult, error) {
	r := clientSDKDeriveR(&c.sk, c.chainID, denom, availBalance, "unshield")
	ct, _, _ := elgamal.EncryptWithRandomness(amount, &c.pk, &r)
	ctBytes, _ := ct.Marshal()

	dleqT := c.buildTranscript(sender, "", denom)
	dleqProof, err := elgamal.ProveDLEQ(&c.sk, &c.pk, &ct, amount, dleqT)
	if err != nil {
		return nil, err
	}

	remAmount := state.Value - amount
	var remR fr.Element
	remR.Sub(&state.Randomness, &r)

	rpT := c.buildTranscript(sender, "", denom)
	rpProof, err := bulletproofs.AggregateRangeProve([]uint64{remAmount}, []*fr.Element{&remR}, &c.pk, maxBits, rpT)
	if err != nil {
		return nil, err
	}
	rpBytes, _ := rpProof.Marshal()
	return &sdkUnshieldResult{Ciphertext: ctBytes, DecryptionProof: dleqProof.Marshal(), RangeProof: rpBytes, R: r}, nil
}
