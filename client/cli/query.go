package cli

import (
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

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.Balance(cmd.Context(), &types.QueryBalanceRequest{
				Address: args[0],
				Denom:   args[1],
			})
			if err != nil {
				return fmt.Errorf("query balance: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Address:   %s\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "Denom:     %s\n", args[1])
			fmt.Fprintf(cmd.OutOrStdout(), "Available: %x\n", res.Available)
			fmt.Fprintf(cmd.OutOrStdout(), "Pending:   %x\n", res.Pending)
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

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.Params(cmd.Context(), &types.QueryParamsRequest{})
			if err != nil {
				return fmt.Errorf("query params: %w", err)
			}

			if res.Params == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "(no params set)\n")
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Auditor PubKey:    %x\n", res.Params.AuditorPubKey)
			fmt.Fprintf(cmd.OutOrStdout(), "Max Transfer Bits: %d\n", res.Params.MaxTransferBits)
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

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.AuditorKey(cmd.Context(), &types.QueryAuditorKeyRequest{})
			if err != nil {
				return fmt.Errorf("query auditor key: %w", err)
			}

			if len(res.AuditorPubKey) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Auditor key: (not set)\n")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Auditor key: %x\n", res.AuditorPubKey)
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

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.AccountInfo(cmd.Context(), &types.QueryAccountInfoRequest{
				Address: args[0],
			})
			if err != nil {
				return fmt.Errorf("query account info: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Address:    %s\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "Registered: %v\n", res.Registered)
			if res.Registered {
				fmt.Fprintf(cmd.OutOrStdout(), "Pubkey:     %x\n", res.Pubkey)
			}
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
