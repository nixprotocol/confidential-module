package types

import (
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// MaxEncryptedMemoSize is the maximum size of an encrypted memo in bytes.
	// Plaintext (1024) + ephemeral key (64) + nonce (12) + AES-GCM tag (16) = 1116.
	MaxEncryptedMemoSize = 1024 + 64 + 12 + 16 // 1116
)

// Compile-time interface checks.
var (
	_ sdk.Msg = &MsgRegisterKey{}
	_ sdk.Msg = &MsgShield{}
	_ sdk.Msg = &MsgConfidentialSend{}
	_ sdk.Msg = &MsgApplyPending{}
	_ sdk.Msg = &MsgUnshield{}
	_ sdk.Msg = &MsgSetAuditorKey{}
	_ sdk.Msg = &MsgRotateKey{}
)

// ---------- MsgRegisterKey ----------

func (msg *MsgRegisterKey) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if len(msg.Pubkey) != 64 {
		return ErrInvalidPubkey.Wrapf("pubkey must be 64 bytes, got %d", len(msg.Pubkey))
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
		return ErrDenomNotEnabled.Wrap(err.Error())
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
		return ErrDenomNotEnabled.Wrap(err.Error())
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
	if len(msg.EqualityProof) == 0 {
		return ErrInvalidProof.Wrap("equality proof cannot be empty")
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
		return ErrDenomNotEnabled.Wrap(err.Error())
	}
	if len(msg.NewAvailableUpdate) != 128 {
		return ErrInvalidCiphertext.Wrapf("new_available_update must be 128 bytes, got %d", len(msg.NewAvailableUpdate))
	}
	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
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
		return ErrDenomNotEnabled.Wrap(err.Error())
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
	if len(msg.DecryptionProof) == 0 {
		return ErrInvalidProof.Wrap("decryption proof cannot be empty")
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
		return ErrAuditorKeyNotSet.Wrapf("auditor pubkey must be 64 bytes, got %d", len(msg.Pubkey))
	}
	return nil
}

func (msg *MsgSetAuditorKey) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Authority)
	return []sdk.AccAddress{addr}
}

// ---------- MsgRotateKey ----------

func (msg *MsgRotateKey) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if len(msg.NewPubkey) != 64 {
		return ErrInvalidPubkey.Wrapf("new pubkey must be 64 bytes, got %d", len(msg.NewPubkey))
	}
	if len(msg.ReEncryptedAvailable) != len(msg.EqualityProofs) {
		return ErrInvalidProof.Wrap("re_encrypted_available and equality_proofs must have same length")
	}
	for i, dc := range msg.ReEncryptedAvailable {
		if dc.Denom == "" {
			return ErrDenomNotEnabled.Wrapf("re_encrypted_available[%d]: denom cannot be empty", i)
		}
		if len(dc.Ciphertext) != 128 {
			return ErrInvalidCiphertext.Wrapf("re_encrypted_available[%d]: ciphertext must be 128 bytes, got %d", i, len(dc.Ciphertext))
		}
	}
	for i, dp := range msg.EqualityProofs {
		if dp.Denom == "" {
			return ErrInvalidProof.Wrapf("equality_proofs[%d]: denom cannot be empty", i)
		}
		if len(dp.Proof) == 0 {
			return ErrInvalidProof.Wrapf("equality_proofs[%d]: proof cannot be empty", i)
		}
		// Verify denom consistency.
		if dp.Denom != msg.ReEncryptedAvailable[i].Denom {
			return ErrInvalidProof.Wrapf("equality_proofs[%d]: denom mismatch with re_encrypted_available", i)
		}
	}
	return nil
}

func (msg *MsgRotateKey) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}
