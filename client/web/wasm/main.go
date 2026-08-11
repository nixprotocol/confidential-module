package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"syscall/js"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/hkdf"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"

	confidentialcrypto "github.com/nixprotocol/confidential-module/crypto"
)

// bsgsTable is the package-level BSGS decryption table, initialized by wasmInitBSGS.
var bsgsTable *elgamal.DecryptionTable

// ---------------------------------------------------------------------------
// Deterministic randomness derivation (matches client/sdk/randomness.go)
// ---------------------------------------------------------------------------

// Operation types for domain separation.
const (
	opShield       = "shield"
	opSendSender   = "send/sender"
	opSendReceiver = "send/receiver"
	opSendAuditor  = "send/auditor"
	opApplyPending = "apply_pending"
	opUnshield     = "unshield"

	// Blinding factors for the Pedersen commitments the range proofs are taken
	// over. Must match client/sdk/randomness.go.
	opSendTransferBlinding      = "send/blinding/transfer"
	opSendRemainingBlinding     = "send/blinding/remaining"
	opUnshieldRemainingBlinding = "unshield/blinding/remaining"
)

// minSendAmount mirrors client/sdk.DefaultMinSendAmount.
const minSendAmount uint64 = 1000

// derivationContext identifies the exact operation randomness is derived for.
// Must stay byte-identical to client/sdk.DerivationContext.
//
// Binding Amount and Receiver is what stops a transaction that was evicted and
// rebuilt at a different amount from reusing r: two ciphertexts under the same
// key with the same r publicly leak the difference of their plaintexts.
type derivationContext struct {
	ChainID  string
	Denom    string
	Op       string
	Sequence uint64
	Amount   uint64
	Receiver string
}

func (c derivationContext) encode() []byte {
	out := make([]byte, 0, 64+len(c.ChainID)+len(c.Denom)+len(c.Op)+len(c.Receiver))

	appendField := func(b []byte) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
		out = append(out, lenBuf[:]...)
		out = append(out, b...)
	}
	appendField([]byte(c.ChainID))
	appendField([]byte(c.Denom))
	appendField([]byte(c.Op))
	appendField([]byte(c.Receiver))

	var num [8]byte
	binary.BigEndian.PutUint64(num[:], c.Sequence)
	out = append(out, num[:]...)
	binary.BigEndian.PutUint64(num[:], c.Amount)
	out = append(out, num[:]...)

	return out
}

// deriveRandomness matches the Go SDK's DeriveRandomness exactly — both clients
// produce identical r for identical inputs, enabling cross-client state recovery.
func deriveRandomness(sk *fr.Element, currentBalance []byte, ctx derivationContext) (fr.Element, error) {
	skBytes := sk.Bytes()

	reader := hkdf.New(sha256.New, skBytes[:], currentBalance, ctx.encode())

	var buf [64]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return fr.Element{}, fmt.Errorf("hkdf read: %w", err)
	}

	var r fr.Element
	var rBig big.Int
	rBig.SetBytes(buf[:])
	r.SetBigInt(&rBig)
	return r, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func jsResult(data map[string]interface{}) interface{} {
	return js.ValueOf(data)
}

func jsError(msg string) interface{} {
	return js.ValueOf(map[string]interface{}{"error": msg})
}

func buildTranscript(chainId, sender, receiver, denom string) *elgamal.Transcript {
	t := elgamal.NewTranscript("x/confidential/v1")
	t.AppendBytes("chain_id", []byte(chainId))
	t.AppendBytes("sender", []byte(sender))
	if receiver != "" {
		t.AppendBytes("receiver", []byte(receiver))
	}
	t.AppendBytes("denom", []byte(denom))
	return t
}

func parseSecretKey(skHex string) (fr.Element, error) {
	var sk fr.Element
	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return sk, fmt.Errorf("invalid secret key hex: %w", err)
	}
	sk.SetBytes(skBytes)
	return sk, nil
}

func parsePublicKey(pkHex string) (bn254.G1Affine, error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return bn254.G1Affine{}, fmt.Errorf("invalid public key hex: %w", err)
	}
	pk, err := elgamal.UnmarshalPublicKey(pkBytes)
	if err != nil {
		return bn254.G1Affine{}, fmt.Errorf("invalid public key: %w", err)
	}
	return pk, nil
}

// parseUint reads a non-negative integer argument without panicking.
//
// syscall/js Value.Int() PANICS on a non-number, and an uncaught panic inside a
// js.FuncOf callback halts the whole Go WASM runtime — every later crypto call
// on that page fails. Callers reach these entry points straight from JS, so a
// wrong type is an ordinary input error, not a programming error.
func parseUint(v js.Value, name string, max uint64) (uint64, error) {
	if v.Type() != js.TypeNumber {
		return 0, fmt.Errorf("%s must be a number", name)
	}
	f := v.Float()
	if f < 0 || f != f || f > float64(max) {
		return 0, fmt.Errorf("%s out of range [0, %d]", name, max)
	}
	return uint64(f), nil
}

// guard converts a panic anywhere inside a wasm entry point into a returned
// error, so a single malformed call cannot brick the page session.
func guard(name string, fn func() interface{}) (out interface{}) {
	defer func() {
		if r := recover(); r != nil {
			out = jsError(fmt.Sprintf("%s: internal error: %v", name, r))
		}
	}()
	return fn()
}

// parseAmount reads a uint64 amount passed as a DECIMAL STRING.
//
// Amounts are validated on-chain against params.MaxTransferBits, which allows
// up to 64 bits. A JS number cannot represent integers above 2^53-1 exactly, so
// taking amounts via js.Value.Int() silently corrupts large values. Requiring a
// string — and rejecting a JS number outright rather than coercing it — makes
// that failure impossible instead of silent.
func parseAmount(v js.Value, name string) (uint64, error) {
	if v.Type() != js.TypeString {
		return 0, fmt.Errorf(
			"%s must be a decimal string, not a JS number (values above 2^53 lose precision)", name)
	}
	n, err := strconv.ParseUint(v.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return n, nil
}

// parseMaxBits reads the range-proof bit width the chain will verify against.
//
// This must match the chain's params.MaxTransferBits. Hardcoding 64 here would
// silently produce proofs the chain rejects on any deployment that lowered it.
func parseMaxBits(v js.Value) (int, error) {
	n := v.Int()
	if n <= 0 || n > 64 {
		return 0, fmt.Errorf("maxBits must be in (0, 64], got %d", n)
	}
	return n, nil
}

func parseRandomness(rHex string) (fr.Element, error) {
	var r fr.Element
	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return r, fmt.Errorf("invalid randomness hex: %w", err)
	}
	r.SetBytes(rBytes)
	return r, nil
}

// ---------------------------------------------------------------------------
// 1. wasmDeriveKey(seedHex, counter) -> {pubkeyHex, secretKeyHex}
// ---------------------------------------------------------------------------

func wasmDeriveKey(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("wasmDeriveKey: expected 2 args (seedHex, counter)")
	}

	seedHex := args[0].String()
	counterU, err := parseUint(args[1], "counter", 1<<32-1)
	if err != nil {
		return jsError(err.Error())
	}
	counter := uint32(counterU)

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return jsError(fmt.Sprintf("invalid seed hex: %v", err))
	}

	// HKDF-SHA256 with 48-byte output, matching wallet.go exactly
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)

	hkdfReader := hkdf.New(sha256.New, seed, []byte("x/confidential/elgamal/v1"), counterBytes)
	seed48 := make([]byte, 48)
	if _, err := io.ReadFull(hkdfReader, seed48); err != nil {
		return jsError(fmt.Sprintf("HKDF read failed: %v", err))
	}

	var sk fr.Element
	sk.SetBytes(seed48)

	var pk bn254.G1Affine
	pk.ScalarMultiplication(&elgamal.G, sk.BigInt(new(big.Int)))

	skBytes := sk.Bytes()
	pkBytes := elgamal.MarshalPublicKey(&pk)

	return jsResult(map[string]interface{}{
		"secretKeyHex": hex.EncodeToString(skBytes[:]),
		"pubkeyHex":    hex.EncodeToString(pkBytes),
	})
}

// ---------------------------------------------------------------------------
// wasmRegisterKeyProof(skHex, pkHex, chainId, sender) -> {popHex}
//
// Proof of possession required by MsgRegisterKey. Bound to sender so a proof
// observed on-chain cannot be replayed by another account.
// ---------------------------------------------------------------------------

func wasmRegisterKeyProof(_ js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return jsError("wasmRegisterKeyProof: expected 4 args (skHex, pkHex, chainId, sender)")
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}
	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}
	chainId := args[2].String()
	sender := args[3].String()

	proof, err := elgamal.ProvePossession(&sk, &pk, buildTranscript(chainId, sender, "", ""), nil)
	if err != nil {
		return jsError(fmt.Sprintf("prove possession: %v", err))
	}

	return jsResult(map[string]interface{}{
		"popHex": hex.EncodeToString(proof.Marshal()),
	})
}

// ---------------------------------------------------------------------------
// 2. wasmInitBSGS(halfBits) -> {entries, timeMs}
// ---------------------------------------------------------------------------

func wasmInitBSGS(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return jsError("wasmInitBSGS: expected 1 arg (halfBits)")
	}

	halfBitsU, err := parseUint(args[0], "halfBits", 24) // 2^24 entries caps allocation
	if err != nil {
		return jsError(err.Error())
	}
	halfBits := uint(halfBitsU)
	start := time.Now()
	bsgsTable = elgamal.NewDecryptionTable(halfBits)
	elapsed := time.Since(start)

	return jsResult(map[string]interface{}{
		"entries": int(1 << halfBits),
		"timeMs":  elapsed.Milliseconds(),
	})
}

// ---------------------------------------------------------------------------
// 3. wasmShield(skHex, pkHex, amount, chainId, sender, denom, availBalanceHex)
//    -> {ciphertextHex, proofHex, randomnessHex}
//
//    availBalanceHex: current available balance ciphertext from chain (hex),
//                     or "" for first operation on this denom.
// ---------------------------------------------------------------------------

func wasmShield(_ js.Value, args []js.Value) interface{} {
	if len(args) < 8 {
		return jsError("wasmShield: expected 8 args (skHex, pkHex, amountStr, chainId, sender, denom, availBalanceHex, accountSequence)")
	}

	// Account sequence: makes randomness unrepeatable across two
	// transactions built from the same balance snapshot.
	nonce, err := parseUint(args[7], "accountSequence", 1<<53-1)
	if err != nil {
		return jsError(err.Error())
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}

	amount, err := parseAmount(args[2], "amount")
	if err != nil {
		return jsError(err.Error())
	}
	chainId := args[3].String()
	sender := args[4].String()
	denom := args[5].String()

	// Parse current available balance for deterministic randomness derivation.
	var availBalance []byte
	availHex := args[6].String()
	if availHex != "" {
		availBalance, err = hex.DecodeString(availHex)
		if err != nil {
			return jsError(fmt.Sprintf("invalid availBalanceHex: %v", err))
		}
	}

	// Derive deterministic randomness.
	r, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opShield,
		Sequence: nonce, Amount: amount, Receiver: "",
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive randomness: %v", err))
	}

	ct, _, err := elgamal.EncryptWithRandomness(amount, &pk, &r)
	if err != nil {
		return jsError(fmt.Sprintf("encryption failed: %v", err))
	}
	ctBytes := ct.Marshal()

	// Generate DLEQ proof with chain context.
	transcript := buildTranscript(chainId, sender, "", denom)
	proof, err := elgamal.ProveDLEQ(&sk, &pk, &ct, amount, transcript, nil)
	if err != nil {
		return jsError(fmt.Sprintf("proof generation failed: %v", err))
	}
	proofBytes := proof.Marshal()
	rBytes := r.Bytes()

	return jsResult(map[string]interface{}{
		"ciphertextHex": hex.EncodeToString(ctBytes),
		"proofHex":      hex.EncodeToString(proofBytes),
		"randomnessHex": hex.EncodeToString(rBytes[:]),
	})
}

// ---------------------------------------------------------------------------
// 4. wasmSend(skHex, senderPkHex, receiverPkHex, auditorPkHex, amount,
//             availAmount, availRandomnessHex, chainId, sender, receiver,
//             denom, availBalanceHex)
//    -> {senderCtHex, receiverCtHex, auditorCtHex, eqProofHex, rangeProofHex,
//        newAvailRandomnessHex}
// ---------------------------------------------------------------------------

func wasmSend(_ js.Value, args []js.Value) interface{} {
	if len(args) < 14 {
		return jsError("wasmSend: expected 14 args (…, availBalanceHex, accountSequence, maxBits); amounts are decimal strings")
	}

	// Account sequence: makes randomness unrepeatable across two
	// transactions built from the same balance snapshot.
	nonce, err := parseUint(args[12], "accountSequence", 1<<53-1)
	if err != nil {
		return jsError(err.Error())
	}
	maxBits, err := parseMaxBits(args[13])
	if err != nil {
		return jsError(err.Error())
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	senderPk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(fmt.Sprintf("sender pk: %v", err))
	}

	receiverPk, err := parsePublicKey(args[2].String())
	if err != nil {
		return jsError(fmt.Sprintf("receiver pk: %v", err))
	}

	auditorPk, err := parsePublicKey(args[3].String())
	if err != nil {
		return jsError(fmt.Sprintf("auditor pk: %v", err))
	}

	amount, err := parseAmount(args[4], "amount")
	if err != nil {
		return jsError(err.Error())
	}
	availAmount, err := parseAmount(args[5], "availAmount")
	if err != nil {
		return jsError(err.Error())
	}

	// Client-side dust floor, matching client/sdk DefaultMinSendAmount. The
	// chain does not enforce this; it exists so honest wallets cannot cheaply
	// grief a receiver into repeated ApplyPending transactions.
	if amount < minSendAmount {
		return jsError(fmt.Sprintf("amount %d below minimum send amount %d", amount, minSendAmount))
	}

	availRandomness, err := parseRandomness(args[6].String())
	if err != nil {
		return jsError(fmt.Sprintf("avail randomness: %v", err))
	}

	chainId := args[7].String()
	sender := args[8].String()
	receiver := args[9].String()
	denom := args[10].String()

	// Parse current available balance for deterministic randomness.
	var availBalance []byte
	availHex := args[11].String()
	if availHex != "" {
		availBalance, err = hex.DecodeString(availHex)
		if err != nil {
			return jsError(fmt.Sprintf("invalid availBalanceHex: %v", err))
		}
	}

	if availAmount < amount {
		return jsError(fmt.Sprintf("insufficient balance: have %d, want to send %d", availAmount, amount))
	}

	// Derive 3 deterministic randomness values.
	rSender, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opSendSender,
		Sequence: nonce, Amount: amount, Receiver: receiver,
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive sender r: %v", err))
	}
	rReceiver, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opSendReceiver,
		Sequence: nonce, Amount: amount, Receiver: receiver,
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive receiver r: %v", err))
	}
	rAuditor, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opSendAuditor,
		Sequence: nonce, Amount: amount, Receiver: receiver,
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive auditor r: %v", err))
	}

	ctSender, _, err := elgamal.EncryptWithRandomness(amount, &senderPk, &rSender)
	if err != nil {
		return jsError(fmt.Sprintf("sender encryption failed: %v", err))
	}

	ctReceiver, _, err := elgamal.EncryptWithRandomness(amount, &receiverPk, &rReceiver)
	if err != nil {
		return jsError(fmt.Sprintf("receiver encryption failed: %v", err))
	}

	ctAuditor, _, err := elgamal.EncryptWithRandomness(amount, &auditorPk, &rAuditor)
	if err != nil {
		return jsError(fmt.Sprintf("auditor encryption failed: %v", err))
	}

	// Equality proof (3-key).
	eqTranscript := buildTranscript(chainId, sender, receiver, denom)
	eqProof, err := elgamal.ProveEquality(
		amount,
		&rSender, &rReceiver, &rAuditor,
		&senderPk, &receiverPk, &auditorPk,
		&ctSender, &ctReceiver, &ctAuditor,
		eqTranscript,
		nil,
	)
	if err != nil {
		return jsError(fmt.Sprintf("equality proof failed: %v", err))
	}
	eqProofBytes := eqProof.Marshal()

	newBalance := availAmount - amount
	var remainingBlinding fr.Element
	remainingBlinding.Sub(&availRandomness, &rSender)

	// Binding Pedersen commitments for the range proof, each tied to its
	// ciphertext. The range proof cannot be taken over the ciphertexts: their
	// C2 is blinded by the sender's own public key, whose discrete log the
	// sender knows, so C2 can be re-opened to any value.
	sTransfer, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opSendTransferBlinding,
		Sequence: nonce, Amount: amount, Receiver: receiver,
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive transfer blinding: %v", err))
	}
	sRemaining, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opSendRemainingBlinding,
		Sequence: nonce, Amount: amount, Receiver: receiver,
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive remaining blinding: %v", err))
	}

	transferCommitment, transferProof, err := confidentialcrypto.ProveCommitment(
		amount, &rSender, &sTransfer, &senderPk, &ctSender,
		confidentialcrypto.RoleTransfer, buildTranscript(chainId, sender, receiver, denom), nil)
	if err != nil {
		return jsError(fmt.Sprintf("transfer commitment proof failed: %v", err))
	}

	// The chain derives the remaining ciphertext as available - ctSender.
	availCt, err := parseAvailableCiphertext(availBalance)
	if err != nil {
		return jsError(fmt.Sprintf("parse available balance: %v", err))
	}
	remainingCt := elgamal.Sub(availCt, &ctSender)

	remainingCommitment, remainingProof, err := confidentialcrypto.ProveCommitment(
		newBalance, &remainingBlinding, &sRemaining, &senderPk, &remainingCt,
		confidentialcrypto.RoleRemaining, buildTranscript(chainId, sender, receiver, denom), nil)
	if err != nil {
		return jsError(fmt.Sprintf("remaining commitment proof failed: %v", err))
	}

	rpTranscript := buildTranscript(chainId, sender, receiver, denom)
	rangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{amount, newBalance},
		[]*fr.Element{&sTransfer, &sRemaining},
		confidentialcrypto.BlindingBase(),
		maxBits,
		rpTranscript,
	)
	if err != nil {
		return jsError(fmt.Sprintf("range proof failed: %v", err))
	}
	rangeProofBytes, err := rangeProof.Marshal()
	if err != nil {
		return jsError(fmt.Sprintf("range proof marshal failed: %v", err))
	}

	ctSenderBytes := ctSender.Marshal()
	ctReceiverBytes := ctReceiver.Marshal()
	ctAuditorBytes := ctAuditor.Marshal()

	newAvailRBytes := remainingBlinding.Bytes()

	return jsResult(map[string]interface{}{
		"senderCtHex":                 hex.EncodeToString(ctSenderBytes),
		"receiverCtHex":               hex.EncodeToString(ctReceiverBytes),
		"auditorCtHex":                hex.EncodeToString(ctAuditorBytes),
		"eqProofHex":                  hex.EncodeToString(eqProofBytes),
		"rangeProofHex":               hex.EncodeToString(rangeProofBytes),
		"transferCommitmentHex":       hex.EncodeToString(transferCommitment),
		"remainingCommitmentHex":      hex.EncodeToString(remainingCommitment),
		"transferCommitmentProofHex":  hex.EncodeToString(transferProof),
		"remainingCommitmentProofHex": hex.EncodeToString(remainingProof),
		"newAvailRandomnessHex":       hex.EncodeToString(newAvailRBytes[:]),
	})
}

// ---------------------------------------------------------------------------
// 5. wasmApplyPending(skHex, pkHex, pendingCtHex, pendingAmount,
//                     chainId, sender, denom, availBalanceHex)
//    -> {newAvailHex, proofHex, newRandomnessHex}
// ---------------------------------------------------------------------------

func wasmApplyPending(_ js.Value, args []js.Value) interface{} {
	if len(args) < 9 {
		return jsError("wasmApplyPending: expected 9 args (…, availBalanceHex, accountSequence); pendingAmount is a decimal string")
	}

	// Account sequence: makes randomness unrepeatable across two
	// transactions built from the same balance snapshot.
	nonce, err := parseUint(args[8], "accountSequence", 1<<53-1)
	if err != nil {
		return jsError(err.Error())
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}

	pendingCtBytes, err := hex.DecodeString(args[2].String())
	if err != nil {
		return jsError(fmt.Sprintf("invalid pending ciphertext hex: %v", err))
	}
	var pendingCt elgamal.Ciphertext
	if err := pendingCt.Unmarshal(pendingCtBytes); err != nil {
		return jsError(fmt.Sprintf("invalid pending ciphertext: %v", err))
	}

	pendingAmount, err := parseAmount(args[3], "pendingAmount")
	if err != nil {
		return jsError(err.Error())
	}
	chainId := args[4].String()
	sender := args[5].String()
	denom := args[6].String()

	// Parse current available balance for deterministic randomness.
	var availBalance []byte
	availHex := args[7].String()
	if availHex != "" {
		availBalance, err = hex.DecodeString(availHex)
		if err != nil {
			return jsError(fmt.Sprintf("invalid availBalanceHex: %v", err))
		}
	}

	// Derive deterministic randomness for re-encryption.
	//
	// Amount must be the pending total being re-encrypted, not 0. The salt is
	// the *available* balance, which an incoming transfer does not change —
	// incoming funds land in pending. Without binding the pending amount, two
	// ApplyPending attempts straddling an incoming transfer would share rNew
	// while encrypting different values, and the ciphertext difference would
	// hand any observer the incoming amount.
	rNew, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opApplyPending,
		Sequence: nonce, Amount: pendingAmount, Receiver: "",
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive randomness: %v", err))
	}

	newCt, _, err := elgamal.EncryptWithRandomness(pendingAmount, &pk, &rNew)
	if err != nil {
		return jsError(fmt.Sprintf("encryption failed: %v", err))
	}
	newCtBytes := newCt.Marshal()

	transcript := buildTranscript(chainId, sender, "", denom)
	proof, err := elgamal.ProveApplyPending(
		&sk, &pk, &pendingCt, &newCt,
		pendingAmount, &rNew, transcript,
		nil,
	)
	if err != nil {
		return jsError(fmt.Sprintf("proof generation failed: %v", err))
	}
	proofBytes := proof.Marshal()
	rNewBytes := rNew.Bytes()

	return jsResult(map[string]interface{}{
		"newAvailHex":      hex.EncodeToString(newCtBytes),
		"proofHex":         hex.EncodeToString(proofBytes),
		"newRandomnessHex": hex.EncodeToString(rNewBytes[:]),
	})
}

// ---------------------------------------------------------------------------
// 6. wasmUnshield(skHex, pkHex, amount, availAmount, availRandomnessHex,
//                 chainId, sender, denom, availBalanceHex)
//    -> {ciphertextHex, dleqProofHex, rangeProofHex, newAvailRandomnessHex}
// ---------------------------------------------------------------------------

func wasmUnshield(_ js.Value, args []js.Value) interface{} {
	if len(args) < 11 {
		return jsError("wasmUnshield: expected 11 args (…, availBalanceHex, accountSequence, maxBits); amounts are decimal strings")
	}

	// Account sequence: makes randomness unrepeatable across two
	// transactions built from the same balance snapshot.
	nonce, err := parseUint(args[9], "accountSequence", 1<<53-1)
	if err != nil {
		return jsError(err.Error())
	}
	maxBits, err := parseMaxBits(args[10])
	if err != nil {
		return jsError(err.Error())
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}

	amount, err := parseAmount(args[2], "amount")
	if err != nil {
		return jsError(err.Error())
	}
	availAmount, err := parseAmount(args[3], "availAmount")
	if err != nil {
		return jsError(err.Error())
	}

	availRandomness, err := parseRandomness(args[4].String())
	if err != nil {
		return jsError(fmt.Sprintf("avail randomness: %v", err))
	}

	chainId := args[5].String()
	sender := args[6].String()
	denom := args[7].String()

	// Parse current available balance for deterministic randomness.
	var availBalance []byte
	availHex := args[8].String()
	if availHex != "" {
		availBalance, err = hex.DecodeString(availHex)
		if err != nil {
			return jsError(fmt.Sprintf("invalid availBalanceHex: %v", err))
		}
	}

	if availAmount < amount {
		return jsError(fmt.Sprintf("insufficient balance: have %d, want to unshield %d", availAmount, amount))
	}

	// Derive deterministic randomness.
	r, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opUnshield,
		Sequence: nonce, Amount: amount, Receiver: "",
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive randomness: %v", err))
	}

	ct, _, err := elgamal.EncryptWithRandomness(amount, &pk, &r)
	if err != nil {
		return jsError(fmt.Sprintf("encryption failed: %v", err))
	}
	ctBytes := ct.Marshal()

	// DLEQ proof.
	dleqTranscript := buildTranscript(chainId, sender, "", denom)
	dleqProof, err := elgamal.ProveDLEQ(&sk, &pk, &ct, amount, dleqTranscript, nil)
	if err != nil {
		return jsError(fmt.Sprintf("DLEQ proof failed: %v", err))
	}
	dleqProofBytes := dleqProof.Marshal()

	newBalance := availAmount - amount
	var remainingBlinding fr.Element
	remainingBlinding.Sub(&availRandomness, &r)

	// Binding Pedersen commitment for the remaining balance, tied to the
	// (available - ct) ciphertext the chain derives.
	sRemaining, err := deriveRandomness(&sk, availBalance, derivationContext{
		ChainID: chainId, Denom: denom, Op: opUnshieldRemainingBlinding,
		Sequence: nonce, Amount: amount, Receiver: "",
	})
	if err != nil {
		return jsError(fmt.Sprintf("derive remaining blinding: %v", err))
	}

	availCt, err := parseAvailableCiphertext(availBalance)
	if err != nil {
		return jsError(fmt.Sprintf("parse available balance: %v", err))
	}
	remainingCt := elgamal.Sub(availCt, &ct)

	remainingCommitment, remainingProof, err := confidentialcrypto.ProveCommitment(
		newBalance, &remainingBlinding, &sRemaining, &pk, &remainingCt,
		confidentialcrypto.RoleRemaining, buildTranscript(chainId, sender, "", denom), nil)
	if err != nil {
		return jsError(fmt.Sprintf("remaining commitment proof failed: %v", err))
	}

	rpTranscript := buildTranscript(chainId, sender, "", denom)
	rangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{newBalance},
		[]*fr.Element{&sRemaining},
		confidentialcrypto.BlindingBase(),
		maxBits,
		rpTranscript,
	)
	if err != nil {
		return jsError(fmt.Sprintf("range proof failed: %v", err))
	}
	rangeProofBytes, err := rangeProof.Marshal()
	if err != nil {
		return jsError(fmt.Sprintf("range proof marshal failed: %v", err))
	}

	newAvailRBytes := remainingBlinding.Bytes()

	return jsResult(map[string]interface{}{
		"ciphertextHex":               hex.EncodeToString(ctBytes),
		"dleqProofHex":                hex.EncodeToString(dleqProofBytes),
		"rangeProofHex":               hex.EncodeToString(rangeProofBytes),
		"remainingCommitmentHex":      hex.EncodeToString(remainingCommitment),
		"remainingCommitmentProofHex": hex.EncodeToString(remainingProof),
		"newAvailRandomnessHex":       hex.EncodeToString(newAvailRBytes[:]),
	})
}

// parseAvailableCiphertext parses a stored available-balance ciphertext,
// treating nil/empty as the identity ciphertext exactly as the keeper does.
func parseAvailableCiphertext(data []byte) (*elgamal.Ciphertext, error) {
	var ct elgamal.Ciphertext
	if len(data) == 0 {
		return &ct, nil
	}
	if err := ct.Unmarshal(data); err != nil {
		return nil, err
	}
	return &ct, nil
}

// ---------------------------------------------------------------------------
// 7. wasmDecryptBalance(skHex, ciphertextHex) -> {amount}
// ---------------------------------------------------------------------------

func wasmDecryptBalance(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("wasmDecryptBalance: expected 2 args (skHex, ciphertextHex)")
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	ctBytes, err := hex.DecodeString(args[1].String())
	if err != nil {
		return jsError(fmt.Sprintf("invalid ciphertext hex: %v", err))
	}
	var ct elgamal.Ciphertext
	if err := ct.Unmarshal(ctBytes); err != nil {
		return jsError(fmt.Sprintf("invalid ciphertext: %v", err))
	}

	if bsgsTable == nil {
		bsgsTable = elgamal.NewDecryptionTable(16)
	}

	amount, err := elgamal.Decrypt(&ct, &sk, bsgsTable)
	if err != nil {
		return jsError(fmt.Sprintf("decryption failed: %v", err))
	}

	return jsResult(map[string]interface{}{
		"amount": amount,
	})
}

// ---------------------------------------------------------------------------
// 8. wasmEncryptMemo(pkHex, randomnessHex, amount, txAmount)
//    -> {encryptedMemoHex}
//
// Payload layout (48 bytes):
//   [0:32]  randomness (post-tx available randomness)
//   [32:40] amount     (post-tx available balance, big-endian uint64)
//   [40:48] txAmount   (this transaction's amount, big-endian uint64)
//
// Legacy memos written before this field was added are 40 bytes; the
// decoder below handles both lengths for backward compatibility.
// ---------------------------------------------------------------------------

func wasmEncryptMemo(_ js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return jsError("wasmEncryptMemo: expected 4 args (pkHex, randomnessHex, amount, txAmount)")
	}

	pk, err := parsePublicKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	rBytes, err := hex.DecodeString(args[1].String())
	if err != nil {
		return jsError(fmt.Sprintf("invalid randomness hex: %v", err))
	}

	amount, err := parseAmount(args[2], "amount")
	if err != nil {
		return jsError(err.Error())
	}
	txAmount, err := parseAmount(args[3], "txAmount")
	if err != nil {
		return jsError(err.Error())
	}

	payload := make([]byte, 48)
	if len(rBytes) == 32 {
		copy(payload[0:32], rBytes)
	} else if len(rBytes) < 32 {
		copy(payload[32-len(rBytes):32], rBytes)
	} else {
		copy(payload[0:32], rBytes[:32])
	}
	binary.BigEndian.PutUint64(payload[32:40], amount)
	binary.BigEndian.PutUint64(payload[40:48], txAmount)

	encrypted, err := elgamal.EncryptMemo(payload, &pk)
	if err != nil {
		return jsError(fmt.Sprintf("memo encryption failed: %v", err))
	}

	return jsResult(map[string]interface{}{
		"encryptedMemoHex": hex.EncodeToString(encrypted),
	})
}

// ---------------------------------------------------------------------------
// 9. wasmDecryptMemo(skHex, encryptedMemoHex)
//    -> {randomnessHex, amount, txAmount}
//
// Accepts both legacy 40-byte memos and current 48-byte memos. For legacy
// memos, txAmount is reported as 0 (unknown).
// ---------------------------------------------------------------------------

func wasmDecryptMemo(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("wasmDecryptMemo: expected 2 args (skHex, encryptedMemoHex)")
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	encBytes, err := hex.DecodeString(args[1].String())
	if err != nil {
		return jsError(fmt.Sprintf("invalid encrypted memo hex: %v", err))
	}

	payload, err := elgamal.DecryptMemo(encBytes, &sk)
	if err != nil {
		return jsError(fmt.Sprintf("memo decryption failed: %v", err))
	}

	if len(payload) < 40 {
		return jsError(fmt.Sprintf("decrypted memo too short: %d bytes, expected at least 40", len(payload)))
	}

	randomnessHex := hex.EncodeToString(payload[0:32])
	amount := binary.BigEndian.Uint64(payload[32:40])
	var txAmount uint64
	if len(payload) >= 48 {
		txAmount = binary.BigEndian.Uint64(payload[40:48])
	}

	return jsResult(map[string]interface{}{
		"randomnessHex": randomnessHex,
		"amount":        amount,
		"txAmount":      txAmount,
	})
}

// ---------------------------------------------------------------------------
// main: register all functions and block forever
// ---------------------------------------------------------------------------

func main() {
	fmt.Println("WASM crypto module loaded")

	js.Global().Set("wasmDeriveKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmDeriveKey", func() interface{} { return wasmDeriveKey(this, args) })
	}))
	js.Global().Set("wasmInitBSGS", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmInitBSGS", func() interface{} { return wasmInitBSGS(this, args) })
	}))
	js.Global().Set("wasmRegisterKeyProof", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmRegisterKeyProof", func() interface{} { return wasmRegisterKeyProof(this, args) })
	}))
	js.Global().Set("wasmShield", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmShield", func() interface{} { return wasmShield(this, args) })
	}))
	js.Global().Set("wasmSend", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmSend", func() interface{} { return wasmSend(this, args) })
	}))
	js.Global().Set("wasmApplyPending", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmApplyPending", func() interface{} { return wasmApplyPending(this, args) })
	}))
	js.Global().Set("wasmUnshield", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmUnshield", func() interface{} { return wasmUnshield(this, args) })
	}))
	js.Global().Set("wasmDecryptBalance", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmDecryptBalance", func() interface{} { return wasmDecryptBalance(this, args) })
	}))
	js.Global().Set("wasmEncryptMemo", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmEncryptMemo", func() interface{} { return wasmEncryptMemo(this, args) })
	}))
	js.Global().Set("wasmDecryptMemo", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return guard("wasmDecryptMemo", func() interface{} { return wasmDecryptMemo(this, args) })
	}))

	fmt.Println("Registered: wasmDeriveKey, wasmInitBSGS, wasmShield, wasmSend, wasmApplyPending, wasmUnshield, wasmDecryptBalance, wasmEncryptMemo, wasmDecryptMemo")

	select {}
}
