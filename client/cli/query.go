package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

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
			_ = clientCtx // will be used for gRPC queries once proto definitions are added

			fmt.Fprintf(cmd.OutOrStdout(), "Query balance for %s denom %s\n", args[0], args[1])
			fmt.Fprintf(cmd.OutOrStdout(), "Note: Full gRPC query integration requires proto definitions.\n")
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
			_ = clientCtx

			params := types.DefaultParams()
			bz, _ := json.MarshalIndent(params, "", "  ")
			fmt.Fprintf(cmd.OutOrStdout(), "Default Params:\n%s\n", string(bz))
			fmt.Fprintf(cmd.OutOrStdout(), "Note: Full gRPC query integration requires proto definitions.\n")
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
			_ = clientCtx

			fmt.Fprintf(cmd.OutOrStdout(), "Query auditor key\n")
			fmt.Fprintf(cmd.OutOrStdout(), "Note: Full gRPC query integration requires proto definitions.\n")
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
			_ = clientCtx

			fmt.Fprintf(cmd.OutOrStdout(), "Query account info for %s\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "Note: Full gRPC query integration requires proto definitions.\n")
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
