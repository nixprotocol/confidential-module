package keeper

import (
	"context"
	"encoding/hex"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/confidential-module/types"
)

type queryServer struct {
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface.
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = queryServer{}

// Balance returns the available and pending encrypted balances for an account and denomination.
func (q queryServer) Balance(ctx context.Context, req *types.QueryBalanceRequest) (*types.QueryBalanceResponse, error) {
	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, err
	}

	if err := sdk.ValidateDenom(req.Denom); err != nil {
		return nil, types.ErrDenomNotEnabled.Wrap(err.Error())
	}

	availBytes, err := q.GetAvailableBalance(ctx, addr.Bytes(), req.Denom)
	if err != nil {
		return nil, err
	}

	pendBytes, err := q.GetPendingBalance(ctx, addr.Bytes(), req.Denom)
	if err != nil {
		return nil, err
	}

	return &types.QueryBalanceResponse{
		Available: hex.EncodeToString(availBytes),
		Pending:   hex.EncodeToString(pendBytes),
	}, nil
}

// AuditorKey returns the current auditor public key.
func (q queryServer) AuditorKey(ctx context.Context, _ *types.QueryAuditorKeyRequest) (*types.QueryAuditorKeyResponse, error) {
	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryAuditorKeyResponse{
		AuditorPubKey: hex.EncodeToString(params.AuditorPubKey),
	}, nil
}

// Params returns the module parameters.
func (q queryServer) Params(ctx context.Context, _ *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryParamsResponse{
		Params: params,
	}, nil
}

// AccountInfo returns public key, key counter, and registration status for an account.
func (q queryServer) AccountInfo(ctx context.Context, req *types.QueryAccountInfoRequest) (*types.QueryAccountInfoResponse, error) {
	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, err
	}
	addrBytes := addr.Bytes()

	pkBytes, err := q.GetAccountPubkey(ctx, addrBytes)
	if err != nil {
		return nil, err
	}

	if pkBytes == nil {
		return &types.QueryAccountInfoResponse{
			Pubkey:     "",
			KeyCounter: 0,
			Registered: false,
		}, nil
	}

	counter, err := q.GetKeyCounter(ctx, addrBytes)
	if err != nil {
		return nil, err
	}

	return &types.QueryAccountInfoResponse{
		Pubkey:     hex.EncodeToString(pkBytes),
		KeyCounter: counter,
		Registered: true,
	}, nil
}
