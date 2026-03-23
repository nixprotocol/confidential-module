package types

import "context"

// ---------- Query Request/Response Types ----------

// QueryBalanceRequest is the request type for the Balance query.
type QueryBalanceRequest struct {
	Address string `json:"address"`
	Denom   string `json:"denom"`
}

// QueryBalanceResponse is the response type for the Balance query.
type QueryBalanceResponse struct {
	Available string `json:"available"` // hex-encoded 128-byte ciphertext
	Pending   string `json:"pending"`   // hex-encoded 128-byte ciphertext
}

// QueryAuditorKeyRequest is the request type for the AuditorKey query.
type QueryAuditorKeyRequest struct{}

// QueryAuditorKeyResponse is the response type for the AuditorKey query.
type QueryAuditorKeyResponse struct {
	AuditorPubKey string `json:"auditor_pub_key"` // hex-encoded 64 bytes
}

// QueryParamsRequest is the request type for the Params query.
type QueryParamsRequest struct{}

// QueryParamsResponse is the response type for the Params query.
type QueryParamsResponse struct {
	Params Params `json:"params"`
}

// QueryAccountInfoRequest is the request type for the AccountInfo query.
type QueryAccountInfoRequest struct {
	Address string `json:"address"`
}

// QueryAccountInfoResponse is the response type for the AccountInfo query.
type QueryAccountInfoResponse struct {
	Pubkey     string `json:"pubkey"`      // hex-encoded 64 bytes
	KeyCounter uint32 `json:"key_counter"`
	Registered bool   `json:"registered"`
}

// QueryServer defines the query server interface for the confidential module.
type QueryServer interface {
	Balance(context.Context, *QueryBalanceRequest) (*QueryBalanceResponse, error)
	AuditorKey(context.Context, *QueryAuditorKeyRequest) (*QueryAuditorKeyResponse, error)
	Params(context.Context, *QueryParamsRequest) (*QueryParamsResponse, error)
	AccountInfo(context.Context, *QueryAccountInfoRequest) (*QueryAccountInfoResponse, error)
}
