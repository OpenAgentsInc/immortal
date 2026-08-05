package immortalboltzadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
)

const MappingRevision = "openagents.mkt-swp.boltz-released-client.v2"
const maximumRawTransactionBytes = 1_000_000

var (
	ErrInvalidProfile             = errors.New("invalid Immortal Boltz profile")
	ErrInvalidFundingRequest      = errors.New("invalid funding request")
	ErrInvalidPreparedFunding     = errors.New("invalid prepared funding")
	ErrBilateralApprovalMismatch  = errors.New("bilateral Contract approval mismatch")
	ErrScriptPathExitNotPersisted = errors.New("script-path exit package not persisted")
)

type RouteShape struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

var releasedRouteShapes = []RouteShape{
	{Method: "GET", Path: "/v2/version"},
	{Method: "GET", Path: "/v2/swap/submarine"},
	{Method: "POST", Path: "/v2/swap/submarine"},
	{Method: "POST", Path: "/v2/swap/submarine/:id/finalize"},
	{Method: "GET", Path: "/v2/swap/reverse"},
	{Method: "POST", Path: "/v2/swap/reverse"},
	{Method: "GET", Path: "/v2/ws"},
	{Method: "GET", Path: "/v2/swap/submarine/:id/transaction"},
	{Method: "GET", Path: "/v2/swap/submarine/:id/preimage"},
	{Method: "GET", Path: "/v2/chain/BTC/fee"},
	{Method: "GET", Path: "/v2/chain/BTC/height"},
	{Method: "GET", Path: "/v2/chain/BTC/transaction/:txid"},
	{Method: "POST", Path: "/v2/chain/BTC/transaction"},
}

func ReleasedRouteShapes() []RouteShape {
	result := make([]RouteShape, len(releasedRouteShapes))
	copy(result, releasedRouteShapes)
	return result
}

type Profile struct {
	PartialSignaturesDisabled    bool
	ChainPairsDisabled           bool
	CooperativeEndpointsDisabled bool
	ProviderWebSocketURL         string
}

type FundingRequest struct {
	SessionID  string
	Address    string
	AmountSats uint64
}

type PinnedSubmarineCreate struct {
	From            string
	To              string
	PairHash        string
	RefundPublicKey string
	Invoice         string
	ReferralID      string
	PreimageHash    string
	Error           string
}

type ProviderSubmarineCreate struct {
	From            string `json:"from"`
	To              string `json:"to"`
	Invoice         string `json:"invoice"`
	PairHash        string `json:"pairHash"`
	RefundPublicKey string `json:"refundPublicKey"`
	MKTSessionID    string `json:"mktSessionId"`
}

type PinnedReverseCreate struct {
	From             string
	To               string
	PreimageHash     string
	ClaimPublicKey   string
	InvoiceAmount    uint64
	OnchainAmount    uint64
	PairHash         string
	ReferralID       string
	Address          string
	AddressSignature string
	Description      string
	DescriptionHash  string
	InvoiceExpiry    uint64
	Error            string
}

type ProviderReverseCreate struct {
	From           string `json:"from"`
	To             string `json:"to"`
	InvoiceAmount  uint64 `json:"invoiceAmount"`
	PreimageHash   string `json:"preimageHash"`
	ClaimPublicKey string `json:"claimPublicKey"`
	PairHash       string `json:"pairHash"`
	MKTSessionID   string `json:"mktSessionId"`
}

func AdaptPinnedSubmarineCreate(request PinnedSubmarineCreate, sessionID string) (ProviderSubmarineCreate, error) {
	if request.From != "BTC" || request.To != "BTC" ||
		request.Invoice == "" || request.PairHash == "" || request.RefundPublicKey == "" ||
		request.ReferralID != "" || request.PreimageHash != "" || request.Error != "" ||
		!validLowerHex32(sessionID) {
		return ProviderSubmarineCreate{}, ErrInvalidFundingRequest
	}
	return ProviderSubmarineCreate{
		From: request.From, To: request.To, Invoice: request.Invoice,
		PairHash: request.PairHash, RefundPublicKey: request.RefundPublicKey,
		MKTSessionID: sessionID,
	}, nil
}

func AdaptPinnedReverseCreate(request PinnedReverseCreate, sessionID string) (ProviderReverseCreate, error) {
	if request.From != "BTC" || request.To != "BTC" || request.InvoiceAmount == 0 ||
		request.PreimageHash == "" || request.ClaimPublicKey == "" || request.PairHash == "" ||
		request.OnchainAmount != 0 || request.ReferralID != "" || request.Address != "" ||
		request.AddressSignature != "" || request.Description != "" ||
		request.DescriptionHash != "" || request.InvoiceExpiry != 0 || request.Error != "" ||
		!validLowerHex32(sessionID) {
		return ProviderReverseCreate{}, ErrInvalidFundingRequest
	}
	return ProviderReverseCreate{
		From: request.From, To: request.To, InvoiceAmount: request.InvoiceAmount,
		PreimageHash: request.PreimageHash, ClaimPublicKey: request.ClaimPublicKey,
		PairHash: request.PairHash, MKTSessionID: sessionID,
	}, nil
}

type PreparedFunding struct {
	RawTransactionHex string
	OutputIndex       uint32
}

type FundingBinding struct {
	SessionID                string
	FinalizePath             string
	RawTransactionHex        string
	FundingTransactionSHA256 string
	OutputIndex              uint32
}

type BilateralApproval struct {
	SessionID                   string
	FinalizePath                string
	FundingTransactionSHA256    string
	OutputIndex                 uint32
	RequesterContractEventID    string
	ProviderContractEventID     string
	ExitPackageSHA256           string
	ExitPackageMode             string
	AuthorizationSnapshotSHA256 string
	ExitPackagePersisted        bool
	ScriptPathOnly              bool
}

type FundingPreparer interface {
	PrepareFunding(context.Context, FundingRequest) (PreparedFunding, error)
}

type ContractFinalizer interface {
	FinalizeSubmarineAndPersistExit(context.Context, FundingBinding) (BilateralApproval, error)
}

type FundingBroadcaster interface {
	BroadcastPreparedFunding(context.Context, PreparedFunding) (string, error)
}

type FundingGate struct {
	preparer    FundingPreparer
	finalizer   ContractFinalizer
	broadcaster FundingBroadcaster
}

func NewFundingGate(
	profile Profile,
	preparer FundingPreparer,
	finalizer ContractFinalizer,
	broadcaster FundingBroadcaster,
) (*FundingGate, error) {
	if !profile.PartialSignaturesDisabled ||
		!profile.ChainPairsDisabled ||
		!profile.CooperativeEndpointsDisabled ||
		!validProviderWebSocketURL(profile.ProviderWebSocketURL) {
		return nil, ErrInvalidProfile
	}
	if preparer == nil || finalizer == nil || broadcaster == nil {
		return nil, ErrInvalidProfile
	}
	return &FundingGate{
		preparer:    preparer,
		finalizer:   finalizer,
		broadcaster: broadcaster,
	}, nil
}

func (gate *FundingGate) FundSubmarine(
	ctx context.Context,
	request FundingRequest,
) (string, error) {
	if !validLowerHex32(request.SessionID) ||
		request.Address == "" || len(request.Address) > 256 ||
		request.AmountSats == 0 {
		return "", ErrInvalidFundingRequest
	}
	prepared, err := gate.preparer.PrepareFunding(ctx, request)
	if err != nil {
		return "", fmt.Errorf("prepare funding: %w", err)
	}
	binding, err := fundingBinding(request, prepared)
	if err != nil {
		return "", err
	}
	approval, err := gate.finalizer.FinalizeSubmarineAndPersistExit(ctx, binding)
	if err != nil {
		return "", fmt.Errorf("finalize and verify bilateral Contracts: %w", err)
	}
	if err := validateApproval(binding, approval); err != nil {
		return "", err
	}
	transactionID, err := gate.broadcaster.BroadcastPreparedFunding(ctx, prepared)
	if err != nil {
		return "", fmt.Errorf("broadcast prepared funding: %w", err)
	}
	return transactionID, nil
}

func fundingBinding(request FundingRequest, prepared PreparedFunding) (FundingBinding, error) {
	raw, err := decodeRawTransaction(prepared.RawTransactionHex)
	if err != nil {
		return FundingBinding{}, err
	}
	digest := sha256.Sum256(raw)
	return FundingBinding{
		SessionID:                request.SessionID,
		FinalizePath:             fmt.Sprintf("/v2/swap/submarine/%s/finalize", request.SessionID),
		RawTransactionHex:        prepared.RawTransactionHex,
		FundingTransactionSHA256: hex.EncodeToString(digest[:]),
		OutputIndex:              prepared.OutputIndex,
	}, nil
}

func decodeRawTransaction(value string) ([]byte, error) {
	if value == "" || len(value)%2 != 0 || len(value)/2 > maximumRawTransactionBytes {
		return nil, ErrInvalidPreparedFunding
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return nil, ErrInvalidPreparedFunding
		}
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidPreparedFunding
	}
	return raw, nil
}

func validateApproval(binding FundingBinding, approval BilateralApproval) error {
	if approval.SessionID != binding.SessionID ||
		approval.FinalizePath != binding.FinalizePath ||
		approval.FundingTransactionSHA256 != binding.FundingTransactionSHA256 ||
		approval.OutputIndex != binding.OutputIndex ||
		!validLowerHex32(approval.RequesterContractEventID) ||
		!validLowerHex32(approval.ProviderContractEventID) ||
		approval.RequesterContractEventID == approval.ProviderContractEventID ||
		!validLowerHex32(approval.ExitPackageSHA256) ||
		!validLowerHex32(approval.AuthorizationSnapshotSHA256) ||
		(approval.ExitPackageMode != "presigned" && approval.ExitPackageMode != "wallet_sign") {
		return ErrBilateralApprovalMismatch
	}
	if !approval.ExitPackagePersisted || !approval.ScriptPathOnly {
		return ErrScriptPathExitNotPersisted
	}
	return nil
}

func validLowerHex32(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validProviderWebSocketURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
		return false
	}
	return parsed.Host != "" &&
		parsed.User == nil &&
		parsed.Opaque == "" &&
		parsed.Path == "/v2/ws" &&
		parsed.RawPath == "" &&
		parsed.RawQuery == "" &&
		!parsed.ForceQuery &&
		parsed.Fragment == ""
}
