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

type MsgRegisterKey struct {
	Sender  string `json:"sender"`
	Pubkey  []byte `json:"pubkey"`  // 64 bytes (uncompressed G1)
	Counter uint32 `json:"counter"` // initial key counter (must be 0 for first registration)
}

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

type MsgShield struct {
	Sender        string `json:"sender"`
	Denom         string `json:"denom"`
	Amount        string `json:"amount"`          // math.Int as string
	Ciphertext    []byte `json:"ciphertext"`      // 128 bytes
	Proof         []byte `json:"proof"`            // DLEQ proof
	EncryptedMemo []byte `json:"encrypted_memo,omitempty"` // optional encrypted memo
}

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

type MsgConfidentialSend struct {
	Sender             string `json:"sender"`
	Receiver           string `json:"receiver"`
	Denom              string `json:"denom"`
	SenderUpdate       []byte `json:"sender_update"`       // 128 bytes
	ReceiverUpdate     []byte `json:"receiver_update"`     // 128 bytes
	AuditorUpdate      []byte `json:"auditor_update"`      // 128 bytes
	RangeProof         []byte `json:"range_proof"`
	EqualityProof      []byte `json:"equality_proof"`
	ReceiverKeyCounter uint32 `json:"receiver_key_counter"`
	EncryptedMemo      []byte `json:"encrypted_memo,omitempty"` // optional memo encrypted to recipient
	AuditorMemo        []byte `json:"auditor_memo,omitempty"`   // optional memo encrypted to auditor
}

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

type MsgApplyPending struct {
	Sender             string `json:"sender"`
	Denom              string `json:"denom"`
	NewAvailableUpdate []byte `json:"new_available_update"` // 128 bytes
	Proof              []byte `json:"proof"`                // ApplyPendingProof
}

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

type MsgUnshield struct {
	Sender          string `json:"sender"`
	Denom           string `json:"denom"`
	Amount          string `json:"amount"`
	Ciphertext      []byte `json:"ciphertext"`       // 128 bytes
	RangeProof      []byte `json:"range_proof"`
	DecryptionProof []byte `json:"decryption_proof"` // DLEQ proof
	EncryptedMemo   []byte `json:"encrypted_memo,omitempty"` // optional encrypted memo
}

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

type MsgSetAuditorKey struct {
	Authority string `json:"authority"`
	Pubkey    []byte `json:"pubkey"` // 64 bytes
}

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

// DenomCiphertext associates a denomination with a re-encrypted ciphertext.
type DenomCiphertext struct {
	Denom      string `json:"denom"`
	Ciphertext []byte `json:"ciphertext"` // 128 bytes
}

// DenomProof associates a denomination with an equality proof.
type DenomProof struct {
	Denom string `json:"denom"`
	Proof []byte `json:"proof"`
}

type MsgRotateKey struct {
	Sender               string            `json:"sender"`
	NewPubkey            []byte            `json:"new_pubkey"`             // 64 bytes
	NewCounter           uint32            `json:"new_counter"`
	ReEncryptedAvailable []DenomCiphertext `json:"re_encrypted_available"`
	EqualityProofs       []DenomProof      `json:"equality_proofs"`
}

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
