// Package crypto holds the commitment/proof construction shared by the keeper,
// the Go SDK client and the WASM client, so all three agree byte-for-byte on
// how range proof commitments are built and bound.
package crypto

import (
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	bulletproofs "github.com/nixprotocol/bulletproofs-bn254"
	elgamal "github.com/nixprotocol/elgamal-bn254"
)

// Roles distinguish the commitment-equality proofs carried by one message, so a
// proof built for one slot cannot be replayed into another.
const (
	RoleTransfer  = "transfer"
	RoleRemaining = "remaining"
)

// BlindingBase returns the generator that range proof commitments are blinded with.
//
// It must be a nothing-up-my-sleeve point whose discrete log with respect to G
// is unknown to everyone. It must never be an account's public key: an account
// knows its own secret key, so a "commitment" blinded by its own public key can
// be re-opened to any value and the range proof over it proves nothing.
func BlindingBase() *bn254.G1Affine {
	return &bulletproofs.H
}

// Commit returns value*G + blinding*H, the binding Pedersen commitment that
// range proofs are taken over.
func Commit(value uint64, blinding *fr.Element) bn254.G1Affine {
	var v fr.Element
	v.SetUint64(value)
	return bulletproofs.PedersenCommitWithBase(&v, &elgamal.G, blinding, BlindingBase())
}

// AppendRole applies the role separator to a transcript. The keeper and the
// clients both go through this so their transcripts cannot drift apart.
func AppendRole(t *elgamal.Transcript, role string) {
	t.AppendBytes("commitment_role", []byte(role))
}

// ProveCommitment builds the Pedersen commitment for value and the proof
// binding it to ct, which must be Enc(value, pk, ctRandomness).
//
// Returns the serialized commitment (64 bytes) and proof (288 bytes), ready to
// drop into a message. transcript must be the message-context transcript; the
// role separator is applied here.
func ProveCommitment(
	value uint64,
	ctRandomness, blinding *fr.Element,
	pk *bn254.G1Affine,
	ct *elgamal.Ciphertext,
	role string,
	transcript *elgamal.Transcript,
	rng io.Reader,
) (commitment []byte, proof []byte, err error) {
	if blinding.IsZero() {
		return nil, nil, fmt.Errorf("commitment blinding must not be zero")
	}

	c := Commit(value, blinding)

	var v fr.Element
	v.SetUint64(value)

	AppendRole(transcript, role)
	p, err := elgamal.ProveCommitmentEquality(&v, ctRandomness, blinding, pk, BlindingBase(), ct, &c, transcript, rng)
	if err != nil {
		return nil, nil, fmt.Errorf("commitment equality proof (%s): %w", role, err)
	}

	return c.Marshal(), p.Marshal(), nil
}
