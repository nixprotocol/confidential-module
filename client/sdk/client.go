package sdk

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// DefaultMinSendAmount is the minimum confidential send amount enforced
// client-side. This makes dust-send griefing of ApplyPending uneconomical:
// an attacker must burn at least this amount per griefing attempt.
const DefaultMinSendAmount uint64 = 1000

// Client provides confidential transaction operations using deterministic
// randomness derived from the secret key and on-chain state.
type Client struct {
	sk             fr.Element
	pk             bn254.G1Affine
	chainID        string
	MinSendAmount  uint64 // minimum send amount; defaults to DefaultMinSendAmount
}

// NewClient creates a new confidential client.
func NewClient(sk *fr.Element, pk *bn254.G1Affine, chainID string) *Client {
	return &Client{
		sk:            *sk,
		pk:            *pk,
		chainID:       chainID,
		MinSendAmount: DefaultMinSendAmount,
	}
}

// PublicKey returns the client's ElGamal public key bytes (64 bytes).
func (c *Client) PublicKey() []byte {
	return elgamal.MarshalPublicKey(&c.pk)
}

// buildTranscript creates a Fiat-Shamir transcript matching the on-chain
// buildTranscript in keeper/verify.go.
func (c *Client) buildTranscript(sender, receiver, denom string) *elgamal.Transcript {
	t := elgamal.NewTranscript("x/confidential/v1")
	t.AppendBytes("chain_id", []byte(c.chainID))
	t.AppendBytes("sender", []byte(sender))
	if receiver != "" {
		t.AppendBytes("receiver", []byte(receiver))
	}
	t.AppendBytes("denom", []byte(denom))
	return t
}

// ShieldResult contains the outputs of a Shield operation.
type ShieldResult struct {
	Ciphertext []byte // 128-byte encrypted amount
	Proof      []byte // DLEQ proof bytes
	R          fr.Element
}

// Shield creates a shield transaction: encrypts amount under the client's
// public key with deterministic randomness and produces a DLEQ proof.
func (c *Client) Shield(sender, denom string, amount uint64, currentAvailBalance []byte) (*ShieldResult, error) {
	r, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpShield)
	if err != nil {
		return nil, fmt.Errorf("derive randomness: %w", err)
	}

	ct, _, err := elgamal.EncryptWithRandomness(amount, &c.pk, &r)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	ctBytes, err := ct.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ciphertext: %w", err)
	}

	transcript := c.buildTranscript(sender, "", denom)
	proof, err := elgamal.ProveDLEQ(&c.sk, &c.pk, &ct, amount, transcript)
	if err != nil {
		return nil, fmt.Errorf("prove DLEQ: %w", err)
	}

	return &ShieldResult{
		Ciphertext: ctBytes,
		Proof:      proof.Marshal(),
		R:          r,
	}, nil
}

// SendResult contains the outputs of a ConfidentialSend operation.
type SendResult struct {
	SenderUpdate   []byte // 128-byte sender ciphertext
	ReceiverUpdate []byte // 128-byte receiver ciphertext
	AuditorUpdate  []byte // 128-byte auditor ciphertext
	EqualityProof  []byte
	RangeProof     []byte
	RSender        fr.Element
}

// Send creates a confidential send transaction. The caller must provide the
// current balance state (for range proof construction) and the receiver/auditor
// public keys.
func (c *Client) Send(
	sender, receiver, denom string,
	amount uint64,
	state *BalanceState,
	currentAvailBalance []byte,
	receiverPk, auditorPk *bn254.G1Affine,
	maxBits int,
) (*SendResult, error) {
	if receiverPk == nil {
		return nil, fmt.Errorf("receiverPk is nil")
	}
	if auditorPk == nil {
		return nil, fmt.Errorf("auditorPk is nil")
	}
	if c.MinSendAmount > 0 && amount < c.MinSendAmount {
		return nil, fmt.Errorf("amount %d below minimum send amount %d", amount, c.MinSendAmount)
	}
	if !state.RandomnessKnown {
		return nil, fmt.Errorf("randomness unknown: recover state via ApplyPending or Shield first")
	}
	if amount > state.Value {
		return nil, fmt.Errorf("insufficient balance: have %d, sending %d", state.Value, amount)
	}

	// Derive three independent randomness values.
	rSender, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpSendSender)
	if err != nil {
		return nil, fmt.Errorf("derive sender r: %w", err)
	}
	rReceiver, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpSendReceiver)
	if err != nil {
		return nil, fmt.Errorf("derive receiver r: %w", err)
	}
	rAuditor, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpSendAuditor)
	if err != nil {
		return nil, fmt.Errorf("derive auditor r: %w", err)
	}

	// Encrypt under each key.
	senderCt, _, err := elgamal.EncryptWithRandomness(amount, &c.pk, &rSender)
	if err != nil {
		return nil, fmt.Errorf("encrypt sender: %w", err)
	}
	receiverCt, _, err := elgamal.EncryptWithRandomness(amount, receiverPk, &rReceiver)
	if err != nil {
		return nil, fmt.Errorf("encrypt receiver: %w", err)
	}
	auditorCt, _, err := elgamal.EncryptWithRandomness(amount, auditorPk, &rAuditor)
	if err != nil {
		return nil, fmt.Errorf("encrypt auditor: %w", err)
	}

	// Equality proof: all three ciphertexts encrypt the same amount.
	eqTranscript := c.buildTranscript(sender, receiver, denom)
	eqProof, err := elgamal.ProveEquality(
		amount,
		&rSender, &rReceiver, &rAuditor,
		&c.pk, receiverPk, auditorPk,
		&senderCt, &receiverCt, &auditorCt,
		eqTranscript,
	)
	if err != nil {
		return nil, fmt.Errorf("prove equality: %w", err)
	}

	// Range proof: transfer amount >= 0 AND remaining balance >= 0.
	remainingAmount := state.Value - amount
	var remainingR fr.Element
	remainingR.Sub(&state.Randomness, &rSender)

	rangeTranscript := c.buildTranscript(sender, receiver, denom)
	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{amount, remainingAmount},
		[]*fr.Element{&rSender, &remainingR},
		&c.pk, // H base = sender's pk
		maxBits,
		rangeTranscript,
	)
	if err != nil {
		return nil, fmt.Errorf("prove range: %w", err)
	}
	rangeProofBytes, err := aggProof.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal range proof: %w", err)
	}

	senderCtBytes, _ := senderCt.Marshal()
	receiverCtBytes, _ := receiverCt.Marshal()
	auditorCtBytes, _ := auditorCt.Marshal()

	return &SendResult{
		SenderUpdate:   senderCtBytes,
		ReceiverUpdate: receiverCtBytes,
		AuditorUpdate:  auditorCtBytes,
		EqualityProof:  eqProof.Marshal(),
		RangeProof:     rangeProofBytes,
		RSender:        rSender,
	}, nil
}

// ApplyPendingResult contains the outputs of an ApplyPending operation.
type ApplyPendingResult struct {
	NewAvailableUpdate []byte // 128-byte re-encrypted ciphertext
	Proof              []byte // ApplyPending proof bytes
	RNew               fr.Element
	DecryptedAmount    uint64
}

// ApplyPending creates an apply-pending transaction. The client decrypts the
// pending balance (using a DLOG table), re-encrypts with deterministic
// randomness, and produces the proof.
//
// The decryptionTable should be created via elgamal.NewDecryptionTable(halfBits).
func (c *Client) ApplyPending(
	sender, denom string,
	currentAvailBalance, currentPendBalance []byte,
	decryptionTable elgamal.Decryptor,
) (*ApplyPendingResult, error) {
	// Unmarshal pending ciphertext.
	var pendCt elgamal.Ciphertext
	if err := pendCt.Unmarshal(currentPendBalance); err != nil {
		return nil, fmt.Errorf("unmarshal pending: %w", err)
	}

	// Decrypt pending balance (DLOG solve).
	pendingAmount, err := elgamal.Decrypt(&pendCt, &c.sk, decryptionTable)
	if err != nil {
		return nil, fmt.Errorf("decrypt pending: %w", err)
	}

	// Derive randomness for re-encryption.
	rNew, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpApplyPending)
	if err != nil {
		return nil, fmt.Errorf("derive randomness: %w", err)
	}

	// Re-encrypt the pending amount with known randomness.
	newCt, _, err := elgamal.EncryptWithRandomness(pendingAmount, &c.pk, &rNew)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt: %w", err)
	}

	newCtBytes, err := newCt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal new ct: %w", err)
	}

	// ApplyPending proof.
	transcript := c.buildTranscript(sender, "", denom)
	proof, err := elgamal.ProveApplyPending(&c.sk, &c.pk, &pendCt, &newCt, pendingAmount, &rNew, transcript)
	if err != nil {
		return nil, fmt.Errorf("prove apply pending: %w", err)
	}

	return &ApplyPendingResult{
		NewAvailableUpdate: newCtBytes,
		Proof:              proof.Marshal(),
		RNew:               rNew,
		DecryptedAmount:    pendingAmount,
	}, nil
}

// UnshieldResult contains the outputs of an Unshield operation.
type UnshieldResult struct {
	Ciphertext      []byte // 128-byte encrypted amount
	DecryptionProof []byte // DLEQ proof bytes
	RangeProof      []byte // range proof for remaining balance >= 0
	R               fr.Element
}

// Unshield creates an unshield transaction: encrypts the withdrawal amount,
// produces a DLEQ proof and a range proof that the remaining balance is
// non-negative.
func (c *Client) Unshield(
	sender, denom string,
	amount uint64,
	state *BalanceState,
	currentAvailBalance []byte,
	maxBits int,
) (*UnshieldResult, error) {
	if !state.RandomnessKnown {
		return nil, fmt.Errorf("randomness unknown: recover state via ApplyPending or Shield first")
	}
	if amount > state.Value {
		return nil, fmt.Errorf("insufficient balance: have %d, withdrawing %d", state.Value, amount)
	}

	r, err := DeriveRandomness(&c.sk, c.chainID, denom, currentAvailBalance, OpUnshield)
	if err != nil {
		return nil, fmt.Errorf("derive randomness: %w", err)
	}

	ct, _, err := elgamal.EncryptWithRandomness(amount, &c.pk, &r)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	ctBytes, err := ct.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ciphertext: %w", err)
	}

	// DLEQ proof: ciphertext encrypts the claimed amount.
	dleqTranscript := c.buildTranscript(sender, "", denom)
	dleqProof, err := elgamal.ProveDLEQ(&c.sk, &c.pk, &ct, amount, dleqTranscript)
	if err != nil {
		return nil, fmt.Errorf("prove DLEQ: %w", err)
	}

	// Range proof: remaining balance >= 0.
	remainingAmount := state.Value - amount
	var remainingR fr.Element
	remainingR.Sub(&state.Randomness, &r)

	// Remaining balance commitment is C2 of (avail - ct).
	rangeTranscript := c.buildTranscript(sender, "", denom)
	aggProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{remainingAmount},
		[]*fr.Element{&remainingR},
		&c.pk,
		maxBits,
		rangeTranscript,
	)
	if err != nil {
		return nil, fmt.Errorf("prove range: %w", err)
	}
	rangeProofBytes, err := aggProof.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal range proof: %w", err)
	}

	return &UnshieldResult{
		Ciphertext:      ctBytes,
		DecryptionProof: dleqProof.Marshal(),
		RangeProof:      rangeProofBytes,
		R:               r,
	}, nil
}

// RecoverState reconstructs the BalanceState for a denom by decrypting the
// current available balance and deriving the cumulative randomness from
// operation history. This is the "crash recovery" path.
//
// For simple recovery without replaying history, use RecoverStateSimple which
// only requires the current on-chain balance and a DLOG table. It produces
// correct plaintext but unknown randomness — the caller must then do a
// "rebalance" ApplyPending to regain known randomness.
func (c *Client) RecoverStateSimple(
	denom string,
	currentAvailBalance []byte,
	decryptionTable elgamal.Decryptor,
) (*BalanceState, error) {
	if currentAvailBalance == nil {
		return &BalanceState{}, nil
	}

	var ct elgamal.Ciphertext
	if err := ct.Unmarshal(currentAvailBalance); err != nil {
		return nil, fmt.Errorf("unmarshal available: %w", err)
	}

	value, err := elgamal.Decrypt(&ct, &c.sk, decryptionTable)
	if err != nil {
		return nil, fmt.Errorf("decrypt available: %w", err)
	}

	// Randomness is unknown after simple recovery. The caller should do an
	// ApplyPending (shield 0 is not possible) or track that the next operation
	// needs to re-establish known randomness.
	return &BalanceState{Value: value}, nil
}
