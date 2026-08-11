package keeper_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// browser drives one snippet of JS inside the headless-Chrome page and returns
// the decoded result. The page has already loaded the real crypto.wasm.
type browser struct {
	t   *testing.T
	dir string // e2e dir, holds cdp.mjs
	url string
}

func (b *browser) run(name, script string) map[string]any {
	b.t.Helper()

	path := filepath.Join(b.t.TempDir(), name+".js")
	require.NoError(b.t, os.WriteFile(path, []byte(script), 0o644))

	out, err := exec.Command("node", filepath.Join(b.dir, "cdp.mjs"), b.url, path).Output()
	require.NoError(b.t, err, "%s: driving the browser failed: %s", name, string(out))

	var res map[string]any
	require.NoError(b.t, json.Unmarshal(out, &res), "%s: bad JSON from browser: %s", name, string(out))
	require.Nil(b.t, res["error"], "%s: wasm returned an error: %v", name, res["error"])
	return res
}

func str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	require.True(t, ok, "expected string field %q, got %v", key, m[key])
	return v
}

func unhexOrFail(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestBrowserLifecycle exercises the complete confidential asset lifecycle with
// every proof produced by the real crypto.wasm in a browser and every state
// transition applied by the real on-chain keeper:
//
//	shield (public -> confidential)  "mint"
//	confidential send                 "transfer"
//	apply pending                     receiver claims incoming funds
//	unshield (confidential -> public) "burn"
//
// After each step the resulting ciphertext is handed back to the browser and
// DECRYPTED, so the test asserts on actual balances rather than merely on
// proofs being accepted. A protocol that verified every proof but moved the
// wrong amounts would fail here.
func TestBrowserLifecycle(t *testing.T) {
	dir := os.Getenv("NIX_BROWSER_E2E_DIR")
	url := os.Getenv("NIX_BROWSER_E2E_URL")
	if dir == "" || url == "" {
		t.Skip("set NIX_BROWSER_E2E_DIR and NIX_BROWSER_E2E_URL (see client/web/e2e/run.sh)")
	}
	b := &browser{t: t, dir: dir, url: url}

	const (
		chainID = "test-chain-1"
		denom   = "uatom"

		funded      = 10_000
		shieldAmt   = 5_000
		sendAmt     = 1_000
		unshieldAmt = 200
	)

	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice, bob := aliceAddr.String(), bobAddr.String()

	// ---- keys + proofs of possession, all from the browser -----------------
	keys := b.run("keys", `
(async () => {
  await window.wasmReady;
  const cid = 'test-chain-1';
  const A = '`+alice+`', B = '`+bob+`';
  const ak = wasmDeriveKey('11'.repeat(32), 0);
  const bk = wasmDeriveKey('22'.repeat(32), 0);
  const dk = wasmDeriveKey('33'.repeat(32), 0);
  wasmInitBSGS(16);
  return {
    aliceSk: ak.secretKeyHex, alicePk: ak.pubkeyHex,
    bobSk:   bk.secretKeyHex, bobPk:   bk.pubkeyHex,
    audPk:   dk.pubkeyHex,
    alicePop: wasmRegisterKeyProof(ak.secretKeyHex, ak.pubkeyHex, cid, A).popHex,
    bobPop:   wasmRegisterKeyProof(bk.secretKeyHex, bk.pubkeyHex, cid, B).popHex,
  };
})()`)

	audPk, err := elgamal.UnmarshalPublicKey(unhexOrFail(t, str(t, keys, "audPk")))
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&audPk),
		MaxTransferBits: 64,
	}))
	bankKeeper.fundAccount(alice, denom, funded)

	for _, reg := range []struct{ addr, pk, pop string }{
		{alice, "alicePk", "alicePop"},
		{bob, "bobPk", "bobPop"},
	} {
		_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
			Sender: reg.addr,
			Pubkey: unhexOrFail(t, str(t, keys, reg.pk)),
			Pop:    unhexOrFail(t, str(t, keys, reg.pop)),
		})
		require.NoError(t, err, "registration rejected for %s", reg.addr)
	}

	// ---- MINT: shield 5000 public -> confidential --------------------------
	shield := b.run("shield", `
(async () => {
  await window.wasmReady;
  return wasmShield('`+str(t, keys, "aliceSk")+`', '`+str(t, keys, "alicePk")+`',
    '5000', 'test-chain-1', '`+alice+`', 'uatom', '', 0);
})()`)

	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender: alice, Denom: denom, Amount: "5000",
		Ciphertext: unhexOrFail(t, str(t, shield, "ciphertextHex")),
		Proof:      unhexOrFail(t, str(t, shield, "proofHex")),
	})
	require.NoError(t, err, "browser shield rejected")
	require.Equal(t, sdkmath.NewInt(funded-shieldAmt), bankKeeper.balances[alice][denom],
		"public balance after shield")

	aliceAvail, err := k.GetAvailableBalance(ctx, aliceAddr.Bytes(), denom)
	require.NoError(t, err)
	requireDecrypts(t, b, str(t, keys, "aliceSk"), aliceAvail, shieldAmt, "alice available after shield")

	// ---- TRANSFER: confidential send 1000 alice -> bob ---------------------
	send := b.run("send", `
(async () => {
  await window.wasmReady;
  return wasmSend('`+str(t, keys, "aliceSk")+`', '`+str(t, keys, "alicePk")+`',
    '`+str(t, keys, "bobPk")+`', '`+str(t, keys, "audPk")+`',
    '1000', '5000', '`+str(t, shield, "randomnessHex")+`',
    'test-chain-1', '`+alice+`', '`+bob+`', 'uatom',
    '`+hex.EncodeToString(aliceAvail)+`', 1, 64);
})()`)

	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender: alice, Receiver: bob, Denom: denom,
		SenderUpdate:             unhexOrFail(t, str(t, send, "senderCtHex")),
		ReceiverUpdate:           unhexOrFail(t, str(t, send, "receiverCtHex")),
		AuditorUpdate:            unhexOrFail(t, str(t, send, "auditorCtHex")),
		EqualityProof:            unhexOrFail(t, str(t, send, "eqProofHex")),
		RangeProof:               unhexOrFail(t, str(t, send, "rangeProofHex")),
		TransferCommitment:       unhexOrFail(t, str(t, send, "transferCommitmentHex")),
		RemainingCommitment:      unhexOrFail(t, str(t, send, "remainingCommitmentHex")),
		TransferCommitmentProof:  unhexOrFail(t, str(t, send, "transferCommitmentProofHex")),
		RemainingCommitmentProof: unhexOrFail(t, str(t, send, "remainingCommitmentProofHex")),
	})
	require.NoError(t, err, "browser confidential send rejected")

	// Both sides of the transfer must be right, not just the proofs.
	aliceAvail, err = k.GetAvailableBalance(ctx, aliceAddr.Bytes(), denom)
	require.NoError(t, err)
	requireDecrypts(t, b, str(t, keys, "aliceSk"), aliceAvail, shieldAmt-sendAmt, "alice available after send")

	bobPending, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), denom)
	require.NoError(t, err)
	requireDecrypts(t, b, str(t, keys, "bobSk"), bobPending, sendAmt, "bob pending after send")

	// ---- receiver claims: apply pending ------------------------------------
	apply := b.run("apply", `
(async () => {
  await window.wasmReady;
  return wasmApplyPending('`+str(t, keys, "bobSk")+`', '`+str(t, keys, "bobPk")+`',
    '`+hex.EncodeToString(bobPending)+`', '1000',
    'test-chain-1', '`+bob+`', 'uatom', '', 0);
})()`)

	_, err = msgServer.ApplyPending(ctx, &types.MsgApplyPending{
		Sender: bob, Denom: denom,
		NewAvailableUpdate: unhexOrFail(t, str(t, apply, "newAvailHex")),
		Proof:              unhexOrFail(t, str(t, apply, "proofHex")),
	})
	require.NoError(t, err, "browser apply-pending rejected")

	bobAvail, err := k.GetAvailableBalance(ctx, bobAddr.Bytes(), denom)
	require.NoError(t, err)
	requireDecrypts(t, b, str(t, keys, "bobSk"), bobAvail, sendAmt, "bob available after apply")

	// ---- BURN: unshield 200 confidential -> public -------------------------
	unshield := b.run("unshield", `
(async () => {
  await window.wasmReady;
  return wasmUnshield('`+str(t, keys, "aliceSk")+`', '`+str(t, keys, "alicePk")+`',
    '200', '4000', '`+str(t, send, "newAvailRandomnessHex")+`',
    'test-chain-1', '`+alice+`', 'uatom',
    '`+hex.EncodeToString(aliceAvail)+`', 2, 64);
})()`)

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender: alice, Denom: denom, Amount: "200",
		Ciphertext:               unhexOrFail(t, str(t, unshield, "ciphertextHex")),
		DecryptionProof:          unhexOrFail(t, str(t, unshield, "dleqProofHex")),
		RangeProof:               unhexOrFail(t, str(t, unshield, "rangeProofHex")),
		RemainingCommitment:      unhexOrFail(t, str(t, unshield, "remainingCommitmentHex")),
		RemainingCommitmentProof: unhexOrFail(t, str(t, unshield, "remainingCommitmentProofHex")),
	})
	require.NoError(t, err, "browser unshield rejected")

	require.Equal(t, sdkmath.NewInt(funded-shieldAmt+unshieldAmt), bankKeeper.balances[alice][denom],
		"public balance after unshield")

	aliceAvail, err = k.GetAvailableBalance(ctx, aliceAddr.Bytes(), denom)
	require.NoError(t, err)
	requireDecrypts(t, b, str(t, keys, "aliceSk"), aliceAvail,
		shieldAmt-sendAmt-unshieldAmt, "alice available after unshield")

	// ---- conservation ------------------------------------------------------
	// Everything shielded is still accounted for: alice's confidential
	// remainder + bob's confidential holdings + what alice took back out.
	require.Equal(t, shieldAmt, (shieldAmt-sendAmt-unshieldAmt)+sendAmt+unshieldAmt,
		"value is conserved across the lifecycle")

	t.Logf("lifecycle verified in-browser: shield %d -> send %d -> apply -> unshield %d; "+
		"alice confidential %d, bob confidential %d, alice public %s",
		shieldAmt, sendAmt, unshieldAmt,
		shieldAmt-sendAmt-unshieldAmt, sendAmt, bankKeeper.balances[alice][denom])
}

// requireDecrypts hands a stored ciphertext back to the browser and asserts it
// decrypts to want under the given secret key.
func requireDecrypts(t *testing.T, b *browser, skHex string, ct []byte, want uint64, what string) {
	t.Helper()
	require.NotNil(t, ct, "%s: no ciphertext stored", what)

	res := b.run("decrypt", `
(async () => {
  await window.wasmReady;
  wasmInitBSGS(16);
  return wasmDecryptBalance('`+skHex+`', '`+hex.EncodeToString(ct)+`');
})()`)

	got, ok := res["amount"].(float64)
	require.True(t, ok, "%s: no amount in decrypt result: %v", what, res)
	require.Equal(t, want, uint64(got), "%s", what)
}
