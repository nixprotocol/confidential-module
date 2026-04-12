package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"syscall/js"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/hkdf"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
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
)

// deriveRandomness derives deterministic randomness from the secret key and
// current on-chain state using HKDF-SHA256. This matches the Go SDK's
// DeriveRandomness exactly — both clients produce identical r values for the
// same inputs, enabling cross-client state recovery.
func deriveRandomness(sk *fr.Element, chainID, denom string, currentBalance []byte, opType string) (fr.Element, error) {
	skBytes := sk.Bytes()

	salt := currentBalance

	info := make([]byte, 0, len(chainID)+1+len(denom)+1+len(opType))
	info = append(info, []byte(chainID)...)
	info = append(info, '/')
	info = append(info, []byte(denom)...)
	info = append(info, '/')
	info = append(info, []byte(opType)...)

	reader := hkdf.New(sha256.New, skBytes[:], salt, info)

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
	counter := uint32(args[1].Int())

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
// 2. wasmInitBSGS(halfBits) -> {entries, timeMs}
// ---------------------------------------------------------------------------

func wasmInitBSGS(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return jsError("wasmInitBSGS: expected 1 arg (halfBits)")
	}

	halfBits := uint(args[0].Int())
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
	if len(args) < 7 {
		return jsError("wasmShield: expected 7 args (skHex, pkHex, amount, chainId, sender, denom, availBalanceHex)")
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}

	amount := uint64(args[2].Int())
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
	r, err := deriveRandomness(&sk, chainId, denom, availBalance, opShield)
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
	if len(args) < 12 {
		return jsError("wasmSend: expected 12 args")
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

	amount := uint64(args[4].Int())
	availAmount := uint64(args[5].Int())

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
	rSender, err := deriveRandomness(&sk, chainId, denom, availBalance, opSendSender)
	if err != nil {
		return jsError(fmt.Sprintf("derive sender r: %v", err))
	}
	rReceiver, err := deriveRandomness(&sk, chainId, denom, availBalance, opSendReceiver)
	if err != nil {
		return jsError(fmt.Sprintf("derive receiver r: %v", err))
	}
	rAuditor, err := deriveRandomness(&sk, chainId, denom, availBalance, opSendAuditor)
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

	// Aggregate range proof: [amount, remaining balance].
	newBalance := availAmount - amount
	var remainingBlinding fr.Element
	remainingBlinding.Sub(&availRandomness, &rSender)

	rpTranscript := buildTranscript(chainId, sender, receiver, denom)
	rangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{amount, newBalance},
		[]*fr.Element{&rSender, &remainingBlinding},
		&senderPk,
		64,
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
		"senderCtHex":           hex.EncodeToString(ctSenderBytes),
		"receiverCtHex":         hex.EncodeToString(ctReceiverBytes),
		"auditorCtHex":          hex.EncodeToString(ctAuditorBytes),
		"eqProofHex":            hex.EncodeToString(eqProofBytes),
		"rangeProofHex":         hex.EncodeToString(rangeProofBytes),
		"newAvailRandomnessHex": hex.EncodeToString(newAvailRBytes[:]),
	})
}

// ---------------------------------------------------------------------------
// 5. wasmApplyPending(skHex, pkHex, pendingCtHex, pendingAmount,
//                     chainId, sender, denom, availBalanceHex)
//    -> {newAvailHex, proofHex, newRandomnessHex}
// ---------------------------------------------------------------------------

func wasmApplyPending(_ js.Value, args []js.Value) interface{} {
	if len(args) < 8 {
		return jsError("wasmApplyPending: expected 8 args")
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

	pendingAmount := uint64(args[3].Int())
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
	rNew, err := deriveRandomness(&sk, chainId, denom, availBalance, opApplyPending)
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
	if len(args) < 9 {
		return jsError("wasmUnshield: expected 9 args")
	}

	sk, err := parseSecretKey(args[0].String())
	if err != nil {
		return jsError(err.Error())
	}

	pk, err := parsePublicKey(args[1].String())
	if err != nil {
		return jsError(err.Error())
	}

	amount := uint64(args[2].Int())
	availAmount := uint64(args[3].Int())

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
	r, err := deriveRandomness(&sk, chainId, denom, availBalance, opUnshield)
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

	// Range proof for remaining balance.
	newBalance := availAmount - amount
	var remainingBlinding fr.Element
	remainingBlinding.Sub(&availRandomness, &r)

	rpTranscript := buildTranscript(chainId, sender, "", denom)
	rangeProof, err := bulletproofs.AggregateRangeProve(
		[]uint64{newBalance},
		[]*fr.Element{&remainingBlinding},
		&pk,
		64,
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
		"ciphertextHex":         hex.EncodeToString(ctBytes),
		"dleqProofHex":          hex.EncodeToString(dleqProofBytes),
		"rangeProofHex":         hex.EncodeToString(rangeProofBytes),
		"newAvailRandomnessHex": hex.EncodeToString(newAvailRBytes[:]),
	})
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

	amount := uint64(args[2].Int())
	txAmount := uint64(args[3].Int())

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

	js.Global().Set("wasmDeriveKey", js.FuncOf(wasmDeriveKey))
	js.Global().Set("wasmInitBSGS", js.FuncOf(wasmInitBSGS))
	js.Global().Set("wasmShield", js.FuncOf(wasmShield))
	js.Global().Set("wasmSend", js.FuncOf(wasmSend))
	js.Global().Set("wasmApplyPending", js.FuncOf(wasmApplyPending))
	js.Global().Set("wasmUnshield", js.FuncOf(wasmUnshield))
	js.Global().Set("wasmDecryptBalance", js.FuncOf(wasmDecryptBalance))
	js.Global().Set("wasmEncryptMemo", js.FuncOf(wasmEncryptMemo))
	js.Global().Set("wasmDecryptMemo", js.FuncOf(wasmDecryptMemo))

	fmt.Println("Registered: wasmDeriveKey, wasmInitBSGS, wasmShield, wasmSend, wasmApplyPending, wasmUnshield, wasmDecryptBalance, wasmEncryptMemo, wasmDecryptMemo")

	select {}
}
