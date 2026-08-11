package keeper_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// TestBrowserE2E verifies that proofs produced by the real crypto.wasm running
// in a browser are accepted by the on-chain verifier.
//
// This is the only test that covers the browser client and the keeper together.
// Everything else exercises the Go SDK, so a signature or transcript change that
// broke only the WASM path would otherwise go unnoticed until a user hit it.
//
// It is driven by client/web/e2e/run.sh, which builds crypto.wasm, runs the
// flow in headless Chrome, and re-invokes `go test` with the artifacts. Skipped
// when those artifacts are not present.
func TestBrowserE2E(t *testing.T) {
	phase1Path := os.Getenv("NIX_BROWSER_E2E_PHASE1")
	if phase1Path == "" {
		t.Skip("set NIX_BROWSER_E2E_PHASE1 (see client/web/e2e/run.sh)")
	}

	raw, err := os.ReadFile(phase1Path)
	require.NoError(t, err)

	var p1 struct {
		AliceK struct {
			SecretKeyHex string `json:"secretKeyHex"`
			PubkeyHex    string `json:"pubkeyHex"`
		} `json:"aliceK"`
		BobK struct {
			PubkeyHex string `json:"pubkeyHex"`
		} `json:"bobK"`
		AudK struct {
			PubkeyHex string `json:"pubkeyHex"`
		} `json:"audK"`
		AlicePop struct {
			PopHex string `json:"popHex"`
		} `json:"alicePop"`
		BobPop struct {
			PopHex string `json:"popHex"`
		} `json:"bobPop"`
		Shield struct {
			CiphertextHex string `json:"ciphertextHex"`
			ProofHex      string `json:"proofHex"`
		} `json:"shield"`
		Send struct {
			SenderCtHex                 string `json:"senderCtHex"`
			ReceiverCtHex               string `json:"receiverCtHex"`
			AuditorCtHex                string `json:"auditorCtHex"`
			EqProofHex                  string `json:"eqProofHex"`
			RangeProofHex               string `json:"rangeProofHex"`
			TransferCommitmentHex       string `json:"transferCommitmentHex"`
			RemainingCommitmentHex      string `json:"remainingCommitmentHex"`
			TransferCommitmentProofHex  string `json:"transferCommitmentProofHex"`
			RemainingCommitmentProofHex string `json:"remainingCommitmentProofHex"`
		} `json:"send"`
	}
	require.NoError(t, json.Unmarshal(raw, &p1))

	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}

	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	auditorPk, err := elgamal.UnmarshalPublicKey(unhex(p1.AudK.PubkeyHex))
	require.NoError(t, err)
	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
	}))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice, bob := aliceAddr.String(), bobAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 10000)

	// 1. Registration with browser-generated proofs of possession.
	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: alice, Pubkey: unhex(p1.AliceK.PubkeyHex), Pop: unhex(p1.AlicePop.PopHex),
	})
	require.NoError(t, err, "browser proof of possession (alice) rejected")

	_, err = msgServer.RegisterKey(ctx, &types.MsgRegisterKey{
		Sender: bob, Pubkey: unhex(p1.BobK.PubkeyHex), Pop: unhex(p1.BobPop.PopHex),
	})
	require.NoError(t, err, "browser proof of possession (bob) rejected")

	// 2. Shield 5000 with a browser-generated DLEQ proof.
	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender: alice, Denom: "uatom", Amount: "5000",
		Ciphertext: unhex(p1.Shield.CiphertextHex), Proof: unhex(p1.Shield.ProofHex),
	})
	require.NoError(t, err, "browser shield proof rejected")
	require.Equal(t, sdkmath.NewInt(5000), bankKeeper.balances[alice]["uatom"])

	// 3. Send 1000 with browser-generated equality, commitment-equality and range
	//    proofs. This is the path the mint vulnerability lived on.
	_, err = msgServer.ConfidentialSend(ctx, &types.MsgConfidentialSend{
		Sender: alice, Receiver: bob, Denom: "uatom",
		SenderUpdate:             unhex(p1.Send.SenderCtHex),
		ReceiverUpdate:           unhex(p1.Send.ReceiverCtHex),
		AuditorUpdate:            unhex(p1.Send.AuditorCtHex),
		EqualityProof:            unhex(p1.Send.EqProofHex),
		RangeProof:               unhex(p1.Send.RangeProofHex),
		TransferCommitment:       unhex(p1.Send.TransferCommitmentHex),
		RemainingCommitment:      unhex(p1.Send.RemainingCommitmentHex),
		TransferCommitmentProof:  unhex(p1.Send.TransferCommitmentProofHex),
		RemainingCommitmentProof: unhex(p1.Send.RemainingCommitmentProofHex),
	})
	require.NoError(t, err, "browser confidential send rejected")

	// Bob really received the funds.
	bobPending, err := k.GetPendingBalance(ctx, bobAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.NotNil(t, bobPending)

	// 4. Hand the resulting available balance back to the browser so it can
	//    build the unshield proofs against the exact on-chain ciphertext.
	availBytes, err := k.GetAvailableBalance(ctx, aliceAddr.Bytes(), "uatom")
	require.NoError(t, err)
	require.NotNil(t, availBytes)

	if out := os.Getenv("NIX_BROWSER_E2E_AVAIL_OUT"); out != "" {
		require.NoError(t, os.WriteFile(out, []byte(hex.EncodeToString(availBytes)), 0o644))
		t.Logf("wrote post-send available balance for phase 2: %s", out)
	}

	// 5. If phase 2 already ran, verify the browser-built unshield too.
	phase2Path := os.Getenv("NIX_BROWSER_E2E_PHASE2")
	if phase2Path == "" {
		t.Log("phase 1 verified; run run.sh again to cover unshield")
		return
	}
	raw2, err := os.ReadFile(phase2Path)
	require.NoError(t, err)

	var p2 struct {
		CiphertextHex               string `json:"ciphertextHex"`
		DleqProofHex                string `json:"dleqProofHex"`
		RangeProofHex               string `json:"rangeProofHex"`
		RemainingCommitmentHex      string `json:"remainingCommitmentHex"`
		RemainingCommitmentProofHex string `json:"remainingCommitmentProofHex"`
	}
	require.NoError(t, json.Unmarshal(raw2, &p2))

	_, err = msgServer.Unshield(ctx, &types.MsgUnshield{
		Sender: alice, Denom: "uatom", Amount: "200",
		Ciphertext:               unhex(p2.CiphertextHex),
		DecryptionProof:          unhex(p2.DleqProofHex),
		RangeProof:               unhex(p2.RangeProofHex),
		RemainingCommitment:      unhex(p2.RemainingCommitmentHex),
		RemainingCommitmentProof: unhex(p2.RemainingCommitmentProofHex),
	})
	require.NoError(t, err, "browser unshield rejected")
	require.Equal(t, sdkmath.NewInt(5200), bankKeeper.balances[alice]["uatom"])

	t.Log("browser-generated register/shield/send/unshield all accepted by the chain verifier")
}
