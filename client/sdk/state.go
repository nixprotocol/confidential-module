package sdk

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BalanceState tracks the plaintext value and cumulative randomness for a
// single denom's available balance. This is the client-side state needed to
// create proofs without solving discrete logs.
//
// After each operation the client updates this state:
//   - Shield(amount, r):         value += amount, randomness += r
//   - Send(amount, r_sender):    value -= amount, randomness -= r_sender
//   - Unshield(amount, r):       value -= amount, randomness -= r
//   - ApplyPending(pv, r_new):   value += pv,     randomness += r_new
type BalanceState struct {
	Value           uint64
	Randomness      fr.Element
	RandomnessKnown bool // false after RecoverStateSimple; must ApplyPending to regain
}

// AfterShield updates state after a successful shield.
// Panics if the addition would overflow uint64.
func (s *BalanceState) AfterShield(amount uint64, r *fr.Element) {
	if amount > ^uint64(0)-s.Value {
		panic("BalanceState.AfterShield: overflow")
	}
	s.Value += amount
	s.Randomness.Add(&s.Randomness, r)
	s.RandomnessKnown = true
}

// AfterSend updates state after a successful confidential send (as sender).
// Panics if amount > Value (caller must check before calling).
func (s *BalanceState) AfterSend(amount uint64, rSender *fr.Element) {
	if amount > s.Value {
		panic("BalanceState.AfterSend: underflow")
	}
	s.Value -= amount
	s.Randomness.Sub(&s.Randomness, rSender)
}

// AfterUnshield updates state after a successful unshield.
// Panics if amount > Value (caller must check before calling).
func (s *BalanceState) AfterUnshield(amount uint64, r *fr.Element) {
	if amount > s.Value {
		panic("BalanceState.AfterUnshield: underflow")
	}
	s.Value -= amount
	s.Randomness.Sub(&s.Randomness, r)
}

// AfterApplyPending updates state after a successful apply-pending.
// Panics if the addition would overflow uint64.
func (s *BalanceState) AfterApplyPending(pendingValue uint64, rNew *fr.Element) {
	if pendingValue > ^uint64(0)-s.Value {
		panic("BalanceState.AfterApplyPending: overflow")
	}
	s.Value += pendingValue
	s.Randomness.Add(&s.Randomness, rNew)
	s.RandomnessKnown = true
}
