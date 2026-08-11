package types

import (
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// MaxEncryptedMemoSize is the maximum size of an encrypted memo in bytes.
	// Plaintext (1024) + ephemeral key (64) + nonce (12) + AES-GCM tag (16) = 1116.
	MaxEncryptedMemoSize = 1024 + 64 + 12 + 16 // 1116

	// Maximum proof sizes for ValidateBasic rejection of oversized payloads.
	// Based on actual marshaled sizes with generous headroom (4x) to accommodate
	// future parameter changes. Actual sizes at 64-bit / 2-commitment:
	//   DLEQ: 160, Equality: 512, ApplyPending: 352,
	//   AggregateRange: ~740 (varies with inner-product rounds).
	MaxDLEQProofSize           = 640  // 4x of 160
	MaxEqualityProofSize       = 2048 // 4x of 512
	MaxApplyPendingProofSize   = 1408 // 4x of 352
	MaxAggregateRangeProofSize = 4096 // ~5.5x of 740, accommodates larger bit ranges

	// PedersenCommitmentSize is an uncompressed BN254 G1 point.
	PedersenCommitmentSize = 64

	// CommitmentEqualityProofSize is exact (3 scalars + 3 G1 points), so it is
	// checked for equality rather than as an upper bound.
	CommitmentEqualityProofSize = 3*32 + 3*64 // 288

	// PopProofSize is exact (1 scalar + 1 G1 point).
	PopProofSize = 32 + 64 // 96
)

// Compile-time interface checks.
var (
	_ sdk.Msg = &MsgRegisterKey{}
	_ sdk.Msg = &MsgShield{}
	_ sdk.Msg = &MsgConfidentialSend{}
	_ sdk.Msg = &MsgApplyPending{}
	_ sdk.Msg = &MsgUnshield{}
	_ sdk.Msg = &MsgSetAuditorKey{}
)

// ---------- MsgRegisterKey ----------

func (msg *MsgRegisterKey) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if len(msg.Pubkey) != 64 {
		return ErrInvalidPubkey.Wrapf("pubkey must be 64 bytes, got %d", len(msg.Pubkey))
	}
	if len(msg.Pop) != PopProofSize {
		return ErrInvalidProof.Wrapf("pop must be %d bytes, got %d", PopProofSize, len(msg.Pop))
	}
	return nil
}

func (msg *MsgRegisterKey) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

// ---------- MsgShield ----------

func (msg *MsgShield) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if err := sdk.ValidateDenom(msg.Denom); err != nil {
		return ErrInvalidAmount.Wrap("invalid denom: " + err.Error())
	}
	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok || !amt.IsPositive() {
		return ErrInvalidAmount.Wrap("amount must be a positive integer")
	}
	if len(msg.Ciphertext) != 128 {
		return ErrInvalidCiphertext.Wrapf("ciphertext must be 128 bytes, got %d", len(msg.Ciphertext))
	}
	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
	}
	if len(msg.Proof) > MaxDLEQProofSize {
		return ErrInvalidProof.Wrapf("proof exceeds max size %d bytes", MaxDLEQProofSize)
	}
	if len(msg.EncryptedMemo) > MaxEncryptedMemoSize {
		return ErrInvalidMemo.Wrapf("encrypted_memo exceeds max size %d bytes", MaxEncryptedMemoSize)
	}
	return nil
}

func (msg *MsgShield) Coin() sdk.Coin {
	amt, _ := math.NewIntFromString(msg.Amount)
	return sdk.NewCoin(msg.Denom, amt)
}

func (msg *MsgShield) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

// ---------- MsgConfidentialSend ----------

func (msg *MsgConfidentialSend) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if _, err := sdk.AccAddressFromBech32(msg.Receiver); err != nil {
		return ErrKeyNotRegistered.Wrap("invalid receiver address")
	}
	if msg.Sender == msg.Receiver {
		return ErrInvalidAmount.Wrap("sender and receiver must be different")
	}
	if err := sdk.ValidateDenom(msg.Denom); err != nil {
		return ErrInvalidAmount.Wrap("invalid denom: " + err.Error())
	}
	if len(msg.SenderUpdate) != 128 {
		return ErrInvalidCiphertext.Wrapf("sender_update must be 128 bytes, got %d", len(msg.SenderUpdate))
	}
	if len(msg.ReceiverUpdate) != 128 {
		return ErrInvalidCiphertext.Wrapf("receiver_update must be 128 bytes, got %d", len(msg.ReceiverUpdate))
	}
	if len(msg.AuditorUpdate) != 128 {
		return ErrInvalidCiphertext.Wrapf("auditor_update must be 128 bytes, got %d", len(msg.AuditorUpdate))
	}
	if len(msg.RangeProof) == 0 {
		return ErrInvalidProof.Wrap("range proof cannot be empty")
	}
	if len(msg.RangeProof) > MaxAggregateRangeProofSize {
		return ErrInvalidProof.Wrapf("range proof exceeds max size %d bytes", MaxAggregateRangeProofSize)
	}
	if len(msg.TransferCommitment) != PedersenCommitmentSize {
		return ErrInvalidCiphertext.Wrapf("transfer_commitment must be %d bytes, got %d",
			PedersenCommitmentSize, len(msg.TransferCommitment))
	}
	if len(msg.RemainingCommitment) != PedersenCommitmentSize {
		return ErrInvalidCiphertext.Wrapf("remaining_commitment must be %d bytes, got %d",
			PedersenCommitmentSize, len(msg.RemainingCommitment))
	}
	if len(msg.TransferCommitmentProof) != CommitmentEqualityProofSize {
		return ErrInvalidProof.Wrapf("transfer_commitment_proof must be %d bytes, got %d",
			CommitmentEqualityProofSize, len(msg.TransferCommitmentProof))
	}
	if len(msg.RemainingCommitmentProof) != CommitmentEqualityProofSize {
		return ErrInvalidProof.Wrapf("remaining_commitment_proof must be %d bytes, got %d",
			CommitmentEqualityProofSize, len(msg.RemainingCommitmentProof))
	}
	if len(msg.EqualityProof) == 0 {
		return ErrInvalidProof.Wrap("equality proof cannot be empty")
	}
	if len(msg.EqualityProof) > MaxEqualityProofSize {
		return ErrInvalidProof.Wrapf("equality proof exceeds max size %d bytes", MaxEqualityProofSize)
	}
	if len(msg.EncryptedMemo) > MaxEncryptedMemoSize {
		return ErrInvalidMemo.Wrapf("encrypted_memo exceeds max size %d bytes", MaxEncryptedMemoSize)
	}
	if len(msg.AuditorMemo) > MaxEncryptedMemoSize {
		return ErrInvalidMemo.Wrapf("auditor_memo exceeds max size %d bytes", MaxEncryptedMemoSize)
	}
	return nil
}

func (msg *MsgConfidentialSend) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

// ---------- MsgApplyPending ----------

func (msg *MsgApplyPending) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if err := sdk.ValidateDenom(msg.Denom); err != nil {
		return ErrInvalidAmount.Wrap("invalid denom: " + err.Error())
	}
	if len(msg.NewAvailableUpdate) != 128 {
		return ErrInvalidCiphertext.Wrapf("new_available_update must be 128 bytes, got %d", len(msg.NewAvailableUpdate))
	}
	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
	}
	if len(msg.Proof) > MaxApplyPendingProofSize {
		return ErrInvalidProof.Wrapf("proof exceeds max size %d bytes", MaxApplyPendingProofSize)
	}
	if len(msg.EncryptedMemo) > MaxEncryptedMemoSize {
		return ErrInvalidMemo.Wrapf("encrypted_memo exceeds max size %d bytes", MaxEncryptedMemoSize)
	}
	return nil
}

func (msg *MsgApplyPending) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

// ---------- MsgUnshield ----------

func (msg *MsgUnshield) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if err := sdk.ValidateDenom(msg.Denom); err != nil {
		return ErrInvalidAmount.Wrap("invalid denom: " + err.Error())
	}
	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok || !amt.IsPositive() {
		return ErrInvalidAmount.Wrap("amount must be a positive integer")
	}
	if len(msg.Ciphertext) != 128 {
		return ErrInvalidCiphertext.Wrapf("ciphertext must be 128 bytes, got %d", len(msg.Ciphertext))
	}
	if len(msg.RangeProof) == 0 {
		return ErrInvalidProof.Wrap("range proof cannot be empty")
	}
	if len(msg.RangeProof) > MaxAggregateRangeProofSize {
		return ErrInvalidProof.Wrapf("range proof exceeds max size %d bytes", MaxAggregateRangeProofSize)
	}
	if len(msg.DecryptionProof) == 0 {
		return ErrInvalidProof.Wrap("decryption proof cannot be empty")
	}
	if len(msg.DecryptionProof) > MaxDLEQProofSize {
		return ErrInvalidProof.Wrapf("decryption proof exceeds max size %d bytes", MaxDLEQProofSize)
	}
	if len(msg.RemainingCommitment) != PedersenCommitmentSize {
		return ErrInvalidCiphertext.Wrapf("remaining_commitment must be %d bytes, got %d",
			PedersenCommitmentSize, len(msg.RemainingCommitment))
	}
	if len(msg.RemainingCommitmentProof) != CommitmentEqualityProofSize {
		return ErrInvalidProof.Wrapf("remaining_commitment_proof must be %d bytes, got %d",
			CommitmentEqualityProofSize, len(msg.RemainingCommitmentProof))
	}
	if len(msg.EncryptedMemo) > MaxEncryptedMemoSize {
		return ErrInvalidMemo.Wrapf("encrypted_memo exceeds max size %d bytes", MaxEncryptedMemoSize)
	}
	return nil
}

func (msg *MsgUnshield) Coin() sdk.Coin {
	amt, _ := math.NewIntFromString(msg.Amount)
	return sdk.NewCoin(msg.Denom, amt)
}

func (msg *MsgUnshield) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

// ---------- MsgSetAuditorKey ----------

func (msg *MsgSetAuditorKey) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Authority); err != nil {
		return err
	}
	if len(msg.Pubkey) != 64 {
		return ErrInvalidPubkey.Wrapf("auditor pubkey must be 64 bytes, got %d", len(msg.Pubkey))
	}
	return nil
}

func (msg *MsgSetAuditorKey) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Authority)
	return []sdk.AccAddress{addr}
}
