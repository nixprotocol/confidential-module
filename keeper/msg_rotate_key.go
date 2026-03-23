package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// RotateKey handles the MsgRotateKey message: validates preconditions (counter,
// cooldown, pending balances are zero), verifies equality2 proofs for each
// denom proving old and new ciphertexts encrypt the same balance, then updates
// the account's public key, counter, and balances.
func (k msgServer) RotateKey(goCtx context.Context, msg *types.MsgRotateKey) (*types.MsgRotateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Resolve sender address.
	senderAddr, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}
	addrBytes := senderAddr.Bytes()

	// 2. Check key registered.
	if !k.HasRegisteredKey(ctx, addrBytes) {
		return nil, types.ErrAccountNotRegistered.Wrap("sender has no registered key")
	}

	// 3. Get current counter and check new_counter == current + 1.
	currentCounter, err := k.GetKeyCounter(ctx, addrBytes)
	if err != nil {
		return nil, err
	}
	if msg.NewCounter != currentCounter+1 {
		return nil, types.ErrKeyCounterMismatch.Wrapf("expected %d, got %d", currentCounter+1, msg.NewCounter)
	}

	// 4. Validate the new public key.
	newPk, err := unmarshalPublicKey(msg.NewPubkey)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap(err.Error())
	}

	// 5. Check rotation cooldown.
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	lastRotation, err := k.GetRotationHeight(ctx, addrBytes)
	if err != nil {
		return nil, err
	}
	currentHeight := uint64(ctx.BlockHeight())
	if lastRotation > 0 && currentHeight < lastRotation+params.RotationCooldown {
		return nil, types.ErrRotationCooldown.Wrapf(
			"last rotation at height %d, cooldown %d blocks, current height %d",
			lastRotation, params.RotationCooldown, currentHeight,
		)
	}

	// 6. Check pending == 0 for all enabled denoms (via the pending_is_zero flag).
	// The user must call MsgApplyPending first to drain pending balances.
	for _, denom := range params.EnabledDenoms {
		isZero, err := k.GetPendingIsZero(ctx, addrBytes, denom)
		if err != nil {
			return nil, err
		}
		if !isZero {
			return nil, types.ErrPendingBalanceEmpty.Wrapf(
				"pending balance for denom %s is not zero; call ApplyPending first", denom)
		}
	}

	// 7. Get the old public key.
	oldPkBytes, err := k.GetAccountPubkey(ctx, addrBytes)
	if err != nil {
		return nil, err
	}
	oldPk, err := unmarshalPublicKey(oldPkBytes)
	if err != nil {
		return nil, types.ErrInvalidPubkey.Wrap("stored pubkey: " + err.Error())
	}

	// 8. Verify equality2 proofs for each denom: old available == new available (same plaintext).
	// Build a map of denom -> ciphertext and denom -> proof from the message.
	if len(msg.ReEncryptedAvailable) != len(params.EnabledDenoms) {
		return nil, types.ErrInvalidProof.Wrapf(
			"expected re-encrypted balances for %d denoms, got %d",
			len(params.EnabledDenoms), len(msg.ReEncryptedAvailable),
		)
	}

	denomCiphertexts := make(map[string][]byte, len(msg.ReEncryptedAvailable))
	for _, dc := range msg.ReEncryptedAvailable {
		denomCiphertexts[dc.Denom] = dc.Ciphertext
	}
	denomProofs := make(map[string][]byte, len(msg.EqualityProofs))
	for _, dp := range msg.EqualityProofs {
		denomProofs[dp.Denom] = dp.Proof
	}

	for _, denom := range params.EnabledDenoms {
		newCtBytes, ok := denomCiphertexts[denom]
		if !ok {
			return nil, types.ErrInvalidCiphertext.Wrapf("missing re-encrypted balance for denom %s", denom)
		}
		proofBytes, ok := denomProofs[denom]
		if !ok {
			return nil, types.ErrInvalidProof.Wrapf("missing equality proof for denom %s", denom)
		}

		// Get the old available balance ciphertext.
		oldAvailBytes, err := k.GetAvailableBalance(ctx, addrBytes, denom)
		if err != nil {
			return nil, err
		}
		oldCt, err := unmarshalCiphertext(oldAvailBytes)
		if err != nil {
			return nil, types.ErrInvalidCiphertext.Wrap("stored available balance: " + err.Error())
		}

		newCt, err := unmarshalCiphertext(newCtBytes)
		if err != nil {
			return nil, types.ErrInvalidCiphertext.Wrap("re-encrypted balance: " + err.Error())
		}

		// Verify equality2 proof: Enc(v, oldPk, r1) and Enc(v, newPk, r2) encrypt
		// the same value v.
		if err := k.verifyEquality2(ctx, proofBytes, &oldPk, &newPk, oldCt, newCt, msg.Sender, denom); err != nil {
			return nil, err
		}

		// 9. Replace available balance with the re-encrypted ciphertext.
		if err := k.SetAvailableBalance(ctx, addrBytes, denom, newCtBytes); err != nil {
			return nil, err
		}

		// 10. Reset pending to Encrypt(0) with deterministic randomness (consensus-safe).
		zeroBytes, err := deterministicZeroEncrypt(ctx, &newPk, addrBytes, denom, "rotate/pending")
		if err != nil {
			return nil, types.ErrInvalidCiphertext.Wrapf("failed to encrypt zero for pending reset: %v", err)
		}
		if err := k.SetPendingBalance(ctx, addrBytes, denom, zeroBytes); err != nil {
			return nil, err
		}

		// Keep pending-is-zero flag true (pending was just reset).
		if err := k.SetPendingIsZero(ctx, addrBytes, denom, true); err != nil {
			return nil, err
		}
	}

	// 11. Update pubkey, counter, and rotation height.
	if err := k.SetAccountPubkey(ctx, addrBytes, msg.NewPubkey); err != nil {
		return nil, err
	}
	if err := k.SetKeyCounter(ctx, addrBytes, msg.NewCounter); err != nil {
		return nil, err
	}
	if err := k.SetRotationHeight(ctx, addrBytes, currentHeight); err != nil {
		return nil, err
	}

	// 12. Emit event.
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeRotateKey,
		sdk.NewAttribute(types.AttributeKeySender, msg.Sender),
		sdk.NewAttribute(types.AttributeKeyNewPubkey, fmt.Sprintf("%x", msg.NewPubkey)),
		sdk.NewAttribute(types.AttributeKeyNewCounter, fmt.Sprintf("%d", msg.NewCounter)),
		sdk.NewAttribute(types.AttributeKeyDenomCount, fmt.Sprintf("%d", len(params.EnabledDenoms))),
	))

	return &types.MsgRotateKeyResponse{}, nil
}
