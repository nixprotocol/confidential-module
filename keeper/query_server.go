package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, err
	}

	if err := sdk.ValidateDenom(req.Denom); err != nil {
		return nil, types.ErrInvalidAmount.Wrap("invalid denom: " + err.Error())
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
		Available: availBytes,
		Pending:   pendBytes,
	}, nil
}

// AuditorKey returns the current auditor public key.
func (q queryServer) AuditorKey(ctx context.Context, req *types.QueryAuditorKeyRequest) (*types.QueryAuditorKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryAuditorKeyResponse{
		AuditorPubKey: params.AuditorPubKey,
	}, nil
}

// Params returns the module parameters.
func (q queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryParamsResponse{
		Params: &params,
	}, nil
}

// AccountInfo returns public key and registration status for an account.
func (q queryServer) AccountInfo(ctx context.Context, req *types.QueryAccountInfoRequest) (*types.QueryAccountInfoResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

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
			Pubkey:     nil,
			Registered: false,
		}, nil
	}

	return &types.QueryAccountInfoResponse{
		Pubkey:     pkBytes,
		Registered: true,
	}, nil
}
