package keeper_test

import (
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	confidentialcrypto "github.com/nixprotocol/confidential-module/crypto"
	"github.com/nixprotocol/confidential-module/keeper"
	"github.com/nixprotocol/confidential-module/types"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// attackFixture is a fully-funded, fully-valid confidential send that individual
// attacks then perturb. Every field needed to rebuild any piece is retained, so
// an attack can forge one component while leaving the rest honest — which is the
// only interesting case. An attack that breaks several things at once proves
// nothing about which check caught it.
type attackFixture struct {
	k         keeper.Keeper
	msgServer types.MsgServer
	ctx       sdk.Context

	alice, bob     string
	aliceSk        fr.Element
	alicePk, bobPk bn254.G1Affine
	auditorPk      bn254.G1Affine

	shieldAmt, sendAmt uint64
	shieldR            fr.Element
	shieldCt           elgamal.Ciphertext

	senderCt, receiverCt, auditorCt elgamal.Ciphertext
	rSender                         fr.Element
	remainingR                      fr.Element
	eqProof                         []byte
}

func newAttackFixture(t *testing.T) *attackFixture {
	t.Helper()

	k, bankKeeper, ctx := setupTestKeeper(t)
	msgServer := keeper.NewMsgServerImpl(k)

	aliceSk, alicePk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	bobSk, bobPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)
	_, auditorPk, err := elgamal.KeyGen(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, k.SetParams(ctx, types.Params{
		AuditorPubKey:   elgamal.MarshalPublicKey(&auditorPk),
		MaxTransferBits: 64,
	}))

	aliceAddr := sdk.AccAddress([]byte("alice_______________"))
	bobAddr := sdk.AccAddress([]byte("bob_________________"))
	alice, bob := aliceAddr.String(), bobAddr.String()
	bankKeeper.fundAccount(alice, "uatom", 100_000)

	registerKey(t, msgServer, k, ctx, alice, &aliceSk, &alicePk)
	registerKey(t, msgServer, k, ctx, bob, &bobSk, &bobPk)

	const shieldAmt, sendAmt = uint64(5000), uint64(1000)

	shieldR := randScalar(t)
	shieldCt, _, err := elgamal.EncryptWithRandomness(shieldAmt, &alicePk, &shieldR)
	require.NoError(t, err)
	shieldProof, err := elgamal.ProveDLEQ(&aliceSk, &alicePk, &shieldCt, shieldAmt,
		k.BuildTranscriptForTest(ctx, alice, "", "uatom"), rand.Reader)
	require.NoError(t, err)
	_, err = msgServer.Shield(ctx, &types.MsgShield{
		Sender: alice, Denom: "uatom", Amount: "5000",
		Ciphertext: shieldCt.Marshal(), Proof: shieldProof.Marshal(),
	})
	require.NoError(t, err)

	rSender, rReceiver, rAuditor := randScalar(t), randScalar(t), randScalar(t)
	senderCt, _, err := elgamal.EncryptWithRandomness(sendAmt, &alicePk, &rSender)
	require.NoError(t, err)
	receiverCt, _, err := elgamal.EncryptWithRandomness(sendAmt, &bobPk, &rReceiver)
	require.NoError(t, err)
	auditorCt, _, err := elgamal.EncryptWithRandomness(sendAmt, &auditorPk, &rAuditor)
	require.NoError(t, err)

	eqProof, err := elgamal.ProveEquality(sendAmt, &rSender, &rReceiver, &rAuditor,
		&alicePk, &bobPk, &auditorPk, &senderCt, &receiverCt, &auditorCt,
		k.BuildTranscriptForTest(ctx, alice, bob, "uatom"), rand.Reader)
	require.NoError(t, err)

	var remainingR fr.Element
	remainingR.Sub(&shieldR, &rSender)

	return &attackFixture{
		k: k, msgServer: msgServer, ctx: ctx,
		alice: alice, bob: bob,
		aliceSk: aliceSk, alicePk: alicePk, bobPk: bobPk, auditorPk: auditorPk,
		shieldAmt: shieldAmt, sendAmt: sendAmt, shieldR: shieldR, shieldCt: shieldCt,
		senderCt: senderCt, receiverCt: receiverCt, auditorCt: auditorCt,
		rSender: rSender, remainingR: remainingR, eqProof: eqProof.Marshal(),
	}
}

// proveCommitment builds a commitment-equality proof with fully caller-chosen
// parameters, so attacks can bind the wrong thing on purpose.
func (f *attackFixture) proveCommitment(
	t *testing.T, value uint64, ctRandomness, blinding *fr.Element,
	ct *elgamal.Ciphertext, role, sender, receiver, denom string,
) ([]byte, []byte) {
	t.Helper()
	c, p, err := confidentialcrypto.ProveCommitment(
		value, ctRandomness, blinding, &f.alicePk, ct, role,
		f.k.BuildTranscriptForTest(f.ctx, sender, receiver, denom), rand.Reader)
	require.NoError(t, err)
	return c, p
}

// rangeProof produces an aggregate range proof over the given values/blindings.
func (f *attackFixture) rangeProof(t *testing.T, values []uint64, blindings []*fr.Element) []byte {
	t.Helper()
	p, err := bulletproofs.AggregateRangeProve(values, blindings,
		confidentialcrypto.BlindingBase(), 64,
		f.k.BuildTranscriptForTest(f.ctx, f.alice, f.bob, "uatom"))
	require.NoError(t, err)
	b, err := p.Marshal()
	require.NoError(t, err)
	return b
}

// send submits a MsgConfidentialSend built from the honest fixture, with the
// caller's overrides applied.
func (f *attackFixture) send(mutate func(*types.MsgConfidentialSend)) error {
	msg := &types.MsgConfidentialSend{
		Sender: f.alice, Receiver: f.bob, Denom: "uatom",
		SenderUpdate:   f.senderCt.Marshal(),
		ReceiverUpdate: f.receiverCt.Marshal(),
		AuditorUpdate:  f.auditorCt.Marshal(),
		EqualityProof:  f.eqProof,
	}
	mutate(msg)
	_, err := f.msgServer.ConfidentialSend(f.ctx, msg)
	return err
}

// honest fills in the commitments, binding proofs and range proof correctly.
func (f *attackFixture) honest(t *testing.T, msg *types.MsgConfidentialSend) (sT, sR fr.Element) {
	t.Helper()
	sT, sR = randScalar(t), randScalar(t)

	tc, tp := f.proveCommitment(t, f.sendAmt, &f.rSender, &sT, &f.senderCt,
		confidentialcrypto.RoleTransfer, f.alice, f.bob, "uatom")
	remainingCt := elgamal.Sub(&f.shieldCt, &f.senderCt)
	rc, rp := f.proveCommitment(t, f.shieldAmt-f.sendAmt, &f.remainingR, &sR, &remainingCt,
		confidentialcrypto.RoleRemaining, f.alice, f.bob, "uatom")

	msg.TransferCommitment, msg.TransferCommitmentProof = tc, tp
	msg.RemainingCommitment, msg.RemainingCommitmentProof = rc, rp
	msg.RangeProof = f.rangeProof(t, []uint64{f.sendAmt, f.shieldAmt - f.sendAmt}, []*fr.Element{&sT, &sR})
	return sT, sR
}

// TestAdversarial_ConfidentialSend runs a battery of attacks against the
// commitment/range-proof plumbing. Every one must be rejected.
//
// The control case is deliberately included: if the honest path stopped working
// the attacks would all "pass" for the wrong reason, and the suite would be
// silently worthless.
func TestAdversarial_ConfidentialSend(t *testing.T) {
	t.Run("control/honest send is accepted", func(t *testing.T) {
		f := newAttackFixture(t)
		require.NoError(t, f.send(func(m *types.MsgConfidentialSend) { f.honest(t, m) }))
	})

	t.Run("swap the two commitment-equality proofs between roles", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			m.TransferCommitmentProof, m.RemainingCommitmentProof =
				m.RemainingCommitmentProof, m.TransferCommitmentProof
		})
		require.Error(t, err, "role-swapped proofs must be rejected")
	})

	t.Run("swap the two commitments, keeping their proofs", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			m.TransferCommitment, m.RemainingCommitment = m.RemainingCommitment, m.TransferCommitment
		})
		require.Error(t, err, "swapped commitments must be rejected")
	})

	t.Run("build the remaining proof under the transfer role", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			sT, sR := f.honest(t, m)
			_ = sT
			// Same statement, wrong role label.
			remainingCt := elgamal.Sub(&f.shieldCt, &f.senderCt)
			rc, rp := f.proveCommitment(t, f.shieldAmt-f.sendAmt, &f.remainingR, &sR, &remainingCt,
				confidentialcrypto.RoleTransfer, f.alice, f.bob, "uatom")
			m.RemainingCommitment, m.RemainingCommitmentProof = rc, rp
		})
		require.Error(t, err, "role separator must not be forgeable")
	})

	t.Run("range proof over commitments other than those submitted", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			// Valid range proof, but over unrelated blindings.
			other1, other2 := randScalar(t), randScalar(t)
			m.RangeProof = f.rangeProof(t, []uint64{f.sendAmt, f.shieldAmt - f.sendAmt},
				[]*fr.Element{&other1, &other2})
		})
		require.Error(t, err, "range proof must be bound to the submitted commitments")
	})

	t.Run("bind the remaining commitment to the wrong ciphertext", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			// Prove against senderCt while the chain derives avail - senderCt.
			sR := randScalar(t)
			rc, rp := f.proveCommitment(t, f.sendAmt, &f.rSender, &sR, &f.senderCt,
				confidentialcrypto.RoleRemaining, f.alice, f.bob, "uatom")
			m.RemainingCommitment, m.RemainingCommitmentProof = rc, rp
			m.RangeProof = f.rangeProof(t, []uint64{f.sendAmt, f.sendAmt},
				[]*fr.Element{&sR, &sR})
		})
		require.Error(t, err, "commitment must be bound to the chain-derived ciphertext")
	})

	t.Run("proofs built for a different receiver", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			sT, sR := randScalar(t), randScalar(t)
			tc, tp := f.proveCommitment(t, f.sendAmt, &f.rSender, &sT, &f.senderCt,
				confidentialcrypto.RoleTransfer, f.alice, "cosmos1someoneelse", "uatom")
			remainingCt := elgamal.Sub(&f.shieldCt, &f.senderCt)
			rc, rp := f.proveCommitment(t, f.shieldAmt-f.sendAmt, &f.remainingR, &sR, &remainingCt,
				confidentialcrypto.RoleRemaining, f.alice, "cosmos1someoneelse", "uatom")
			m.TransferCommitment, m.TransferCommitmentProof = tc, tp
			m.RemainingCommitment, m.RemainingCommitmentProof = rc, rp
			m.RangeProof = f.rangeProof(t, []uint64{f.sendAmt, f.shieldAmt - f.sendAmt},
				[]*fr.Element{&sT, &sR})
		})
		require.Error(t, err, "transcript must bind the receiver")
	})

	t.Run("proofs built for a different denom", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			sT, sR := randScalar(t), randScalar(t)
			tc, tp := f.proveCommitment(t, f.sendAmt, &f.rSender, &sT, &f.senderCt,
				confidentialcrypto.RoleTransfer, f.alice, f.bob, "uosmo")
			remainingCt := elgamal.Sub(&f.shieldCt, &f.senderCt)
			rc, rp := f.proveCommitment(t, f.shieldAmt-f.sendAmt, &f.remainingR, &sR, &remainingCt,
				confidentialcrypto.RoleRemaining, f.alice, f.bob, "uosmo")
			m.TransferCommitment, m.TransferCommitmentProof = tc, tp
			m.RemainingCommitment, m.RemainingCommitmentProof = rc, rp
			m.RangeProof = f.rangeProof(t, []uint64{f.sendAmt, f.shieldAmt - f.sendAmt},
				[]*fr.Element{&sT, &sR})
		})
		require.Error(t, err, "transcript must bind the denom")
	})

	t.Run("flip a byte in each commitment-equality proof", func(t *testing.T) {
		f := newAttackFixture(t)
		for _, idx := range []int{0, 31, 96, 200, 287} {
			err := f.send(func(m *types.MsgConfidentialSend) {
				f.honest(t, m)
				m.TransferCommitmentProof[idx] ^= 0x01
			})
			require.Error(t, err, "malleated proof byte %d must be rejected", idx)
		}
	})

	t.Run("identity commitment", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			var identity bn254.G1Affine
			m.RemainingCommitment = identity.Marshal()
		})
		require.Error(t, err, "identity commitment must be rejected")
	})

	t.Run("commitment that is not on the curve", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			junk := make([]byte, 64)
			for i := range junk {
				junk[i] = 0xAB
			}
			m.TransferCommitment = junk
		})
		require.Error(t, err, "off-curve commitment must be rejected")
	})

	t.Run("omit the commitment proofs entirely", func(t *testing.T) {
		f := newAttackFixture(t)
		err := f.send(func(m *types.MsgConfidentialSend) {
			f.honest(t, m)
			m.TransferCommitmentProof = nil
			m.RemainingCommitmentProof = nil
		})
		require.Error(t, err, "missing proofs must be rejected")
	})
}

// TestAdversarial_UnshieldCannotOverstate checks the burn path: the DLEQ proof
// must pin the withdrawn amount to what the ciphertext actually encrypts, so a
// user cannot withdraw more coins than they burn confidentially.
func TestAdversarial_UnshieldCannotOverstate(t *testing.T) {
	f := newAttackFixture(t)

	// Encrypt 100 but claim 4000 on the message.
	r := randScalar(t)
	ct, _, err := elgamal.EncryptWithRandomness(100, &f.alicePk, &r)
	require.NoError(t, err)

	// DLEQ honestly proves 100 — the mismatch is the claimed Amount field.
	dleq, err := elgamal.ProveDLEQ(&f.aliceSk, &f.alicePk, &ct, 100,
		f.k.BuildTranscriptForTest(f.ctx, f.alice, "", "uatom"), rand.Reader)
	require.NoError(t, err)

	var remainingR fr.Element
	remainingR.Sub(&f.shieldR, &r)
	remainingCt := elgamal.Sub(&f.shieldCt, &ct)
	sR := randScalar(t)
	rc, rp := f.proveCommitment(t, f.shieldAmt-100, &remainingR, &sR, &remainingCt,
		confidentialcrypto.RoleRemaining, f.alice, "", "uatom")

	agg, err := bulletproofs.AggregateRangeProve([]uint64{f.shieldAmt - 100},
		[]*fr.Element{&sR}, confidentialcrypto.BlindingBase(), 64,
		f.k.BuildTranscriptForTest(f.ctx, f.alice, "", "uatom"))
	require.NoError(t, err)
	aggBytes, err := agg.Marshal()
	require.NoError(t, err)

	_, err = f.msgServer.Unshield(f.ctx, &types.MsgUnshield{
		Sender: f.alice, Denom: "uatom", Amount: "4000", // lie
		Ciphertext:               ct.Marshal(),
		DecryptionProof:          dleq.Marshal(),
		RangeProof:               aggBytes,
		RemainingCommitment:      rc,
		RemainingCommitmentProof: rp,
	})
	require.Error(t, err, "withdrawing more than the ciphertext encrypts must be rejected")
	require.ErrorIs(t, err, types.ErrInvalidProof)
}
