package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

// GetQueryCmd returns the query commands for the confidential module.
func GetQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Querying commands for the confidential module",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		CmdQueryBalance(),
		CmdQueryParams(),
		CmdQueryAuditorKey(),
		CmdQueryAccountInfo(),
	)

	return cmd
}

// CmdQueryBalance queries the confidential balance for an account and denomination.
func CmdQueryBalance() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "balance [address] [denom]",
		Short: "Query confidential balance for an address and denomination",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			addr, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return err
			}
			denom := args[1]

			// Query available balance from store.
			availKey := types.AvailableBalanceKey(addr.Bytes(), denom)
			availRes, _, err := clientCtx.QueryStore(availKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query available balance: %w", err)
			}

			// Query pending balance from store.
			pendKey := types.PendingBalanceKey(addr.Bytes(), denom)
			pendRes, _, err := clientCtx.QueryStore(pendKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query pending balance: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Address:   %s\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "Denom:     %s\n", denom)
			fmt.Fprintf(cmd.OutOrStdout(), "Available: %x\n", availRes)
			fmt.Fprintf(cmd.OutOrStdout(), "Pending:   %x\n", pendRes)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// CmdQueryParams queries the module parameters.
func CmdQueryParams() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Query the confidential module parameters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			// Query params from store.
			paramsKey := types.ParamsKeyBytes()
			res, _, err := clientCtx.QueryStore(paramsKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query params: %w", err)
			}

			if len(res) == 0 {
				// No params stored; show defaults.
				params := types.DefaultParams()
				bz, _ := json.MarshalIndent(params, "", "  ")
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", string(bz))
				return nil
			}

			var params types.Params
			if err := json.Unmarshal(res, &params); err != nil {
				return fmt.Errorf("unmarshal params: %w", err)
			}
			bz, _ := json.MarshalIndent(params, "", "  ")
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", string(bz))
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// CmdQueryAuditorKey queries the current auditor public key.
func CmdQueryAuditorKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auditor-key",
		Short: "Query the current auditor public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			// Query params from store and extract auditor key.
			paramsKey := types.ParamsKeyBytes()
			res, _, err := clientCtx.QueryStore(paramsKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query params: %w", err)
			}

			if len(res) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Auditor key: (not set)\n")
				return nil
			}

			var params types.Params
			if err := json.Unmarshal(res, &params); err != nil {
				return fmt.Errorf("unmarshal params: %w", err)
			}

			if len(params.AuditorPubKey) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Auditor key: (not set)\n")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Auditor key: %x\n", params.AuditorPubKey)
			}
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// CmdQueryAccountInfo queries account registration info.
func CmdQueryAccountInfo() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account-info [address]",
		Short: "Query account confidential key registration info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			addr, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return err
			}

			// Query pubkey from store.
			pkKey := types.AccountPubkeyKey(addr.Bytes())
			pkRes, _, err := clientCtx.QueryStore(pkKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query account pubkey: %w", err)
			}

			if len(pkRes) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Address:    %s\n", args[0])
				fmt.Fprintf(cmd.OutOrStdout(), "Registered: false\n")
				return nil
			}

			// Query key counter from store.
			kcKey := types.AccountKeyCounterKey(addr.Bytes())
			kcRes, _, err := clientCtx.QueryStore(kcKey, types.StoreKey)
			if err != nil {
				return fmt.Errorf("query key counter: %w", err)
			}

			var counter uint32
			if len(kcRes) == 4 {
				counter = uint32(kcRes[0])<<24 | uint32(kcRes[1])<<16 | uint32(kcRes[2])<<8 | uint32(kcRes[3])
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Address:     %s\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "Registered:  true\n")
			fmt.Fprintf(cmd.OutOrStdout(), "Pubkey:      %x\n", pkRes)
			fmt.Fprintf(cmd.OutOrStdout(), "Key counter: %d\n", counter)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
