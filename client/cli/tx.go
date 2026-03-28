package cli

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"

	"github.com/nixprotocol/confidential-module/types"
)

// GetTxCmd returns the transaction commands for the confidential module.
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Confidential transaction commands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		CmdRegisterKey(),
		CmdShield(),
		CmdConfidentialSend(),
		CmdApplyPending(),
		CmdUnshield(),
		CmdSetAuditorKey(),
		CmdEnableDenoms(),
	)

	return cmd
}

// CmdRegisterKey creates a register-key transaction.
func CmdRegisterKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-key [pubkey-hex]",
		Short: "Register an ElGamal public key for confidential transactions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			pubkey, err := hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("invalid pubkey hex: %w", err)
			}

			msg := &types.MsgRegisterKey{
				Sender:  clientCtx.GetFromAddress().String(),
				Pubkey:  pubkey,
				Counter: 0,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdShield creates a shield transaction (deposit plaintext tokens into confidential pool).
func CmdShield() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shield [denom] [amount] [ciphertext-hex] [proof-hex]",
		Short: "Shield tokens into the confidential balance",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			denom := args[0]
			amount := args[1]

			ciphertext, err := hex.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid ciphertext hex: %w", err)
			}

			proof, err := hex.DecodeString(args[3])
			if err != nil {
				return fmt.Errorf("invalid proof hex: %w", err)
			}

			msg := &types.MsgShield{
				Sender:     clientCtx.GetFromAddress().String(),
				Denom:      denom,
				Amount:     amount,
				Ciphertext: ciphertext,
				Proof:      proof,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdConfidentialSend creates a confidential transfer transaction.
func CmdConfidentialSend() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [receiver] [denom] [sender-update-hex] [receiver-update-hex] [auditor-update-hex] [range-proof-hex] [equality-proof-hex] [receiver-key-counter]",
		Short: "Send a confidential transfer",
		Args:  cobra.ExactArgs(8),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			receiver := args[0]
			denom := args[1]

			senderUpdate, err := hex.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid sender-update hex: %w", err)
			}

			receiverUpdate, err := hex.DecodeString(args[3])
			if err != nil {
				return fmt.Errorf("invalid receiver-update hex: %w", err)
			}

			auditorUpdate, err := hex.DecodeString(args[4])
			if err != nil {
				return fmt.Errorf("invalid auditor-update hex: %w", err)
			}

			rangeProof, err := hex.DecodeString(args[5])
			if err != nil {
				return fmt.Errorf("invalid range-proof hex: %w", err)
			}

			equalityProof, err := hex.DecodeString(args[6])
			if err != nil {
				return fmt.Errorf("invalid equality-proof hex: %w", err)
			}

			receiverKeyCounter, err := strconv.ParseUint(args[7], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid receiver-key-counter: %w", err)
			}

			msg := &types.MsgConfidentialSend{
				Sender:             clientCtx.GetFromAddress().String(),
				Receiver:           receiver,
				Denom:              denom,
				SenderUpdate:       senderUpdate,
				ReceiverUpdate:     receiverUpdate,
				AuditorUpdate:      auditorUpdate,
				RangeProof:         rangeProof,
				EqualityProof:      equalityProof,
				ReceiverKeyCounter: uint32(receiverKeyCounter),
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdApplyPending creates an apply-pending transaction.
func CmdApplyPending() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply-pending [denom] [new-available-update-hex] [proof-hex]",
		Short: "Apply pending balance to available balance",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			denom := args[0]

			newAvailUpdate, err := hex.DecodeString(args[1])
			if err != nil {
				return fmt.Errorf("invalid new-available-update hex: %w", err)
			}

			proof, err := hex.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid proof hex: %w", err)
			}

			msg := &types.MsgApplyPending{
				Sender:             clientCtx.GetFromAddress().String(),
				Denom:              denom,
				NewAvailableUpdate: newAvailUpdate,
				Proof:              proof,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdUnshield creates an unshield transaction (withdraw from confidential balance to plaintext).
func CmdUnshield() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unshield [denom] [amount] [ciphertext-hex] [range-proof-hex] [decryption-proof-hex]",
		Short: "Unshield tokens from the confidential balance",
		Args:  cobra.ExactArgs(5),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			denom := args[0]
			amount := args[1]

			ciphertext, err := hex.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid ciphertext hex: %w", err)
			}

			rangeProof, err := hex.DecodeString(args[3])
			if err != nil {
				return fmt.Errorf("invalid range-proof hex: %w", err)
			}

			decryptionProof, err := hex.DecodeString(args[4])
			if err != nil {
				return fmt.Errorf("invalid decryption-proof hex: %w", err)
			}

			msg := &types.MsgUnshield{
				Sender:          clientCtx.GetFromAddress().String(),
				Denom:           denom,
				Amount:          amount,
				Ciphertext:      ciphertext,
				RangeProof:      rangeProof,
				DecryptionProof: decryptionProof,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdSetAuditorKey creates a set-auditor-key transaction (authority only).
func CmdSetAuditorKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-auditor-key [pubkey-hex]",
		Short: "Set the auditor ElGamal public key (authority only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			pubkey, err := hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("invalid pubkey hex: %w", err)
			}
			if len(pubkey) != 64 {
				return fmt.Errorf("pubkey must be 64 bytes (128 hex chars), got %d bytes", len(pubkey))
			}

			msg := &types.MsgSetAuditorKey{
				Authority: clientCtx.GetFromAddress().String(),
				Pubkey:    pubkey,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// CmdEnableDenoms is a helper that shows how to enable denoms via genesis update.
func CmdEnableDenoms() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable-denoms [denom1] [denom2] ...",
		Short: "Show instructions for enabling denominations",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("To enable denoms for confidential transfers:")
			fmt.Println("1. Stop the chain")
			fmt.Println("2. Edit genesis.json → app_state.confidential.params.enabled_denoms")
			fmt.Printf("3. Set to: %v\n", args)
			fmt.Println("4. Restart the chain")
			fmt.Println()
			fmt.Println("In production, use a governance proposal to update module params.")
			return nil
		},
	}
	return cmd
}
