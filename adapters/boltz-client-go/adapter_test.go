package immortalboltzadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

const sessionID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const requesterContractID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const providerContractID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const exitPackageDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

type adapterFixture struct {
	MappingRevision string `json:"mapping_revision"`
	Clients         struct {
		Go struct {
			RouteShapes           []string `json:"route_shapes"`
			ForbiddenSourceTokens []string `json:"forbidden_source_tokens"`
		} `json:"go"`
	} `json:"clients"`
}

type fakePreparer struct {
	calls    *[]string
	prepared PreparedFunding
	err      error
}

func (fake fakePreparer) PrepareFunding(
	_context context.Context,
	_request FundingRequest,
) (PreparedFunding, error) {
	*fake.calls = append(*fake.calls, "prepare")
	return fake.prepared, fake.err
}

type fakeFinalizer struct {
	calls   *[]string
	approve func(FundingBinding) (BilateralApproval, error)
}

func (fake fakeFinalizer) FinalizeSubmarineAndPersistExit(
	_context context.Context,
	binding FundingBinding,
) (BilateralApproval, error) {
	*fake.calls = append(*fake.calls, "finalize")
	return fake.approve(binding)
}

type fakeBroadcaster struct {
	calls    *[]string
	expected PreparedFunding
}

func (fake fakeBroadcaster) BroadcastPreparedFunding(
	_context context.Context,
	prepared PreparedFunding,
) (string, error) {
	*fake.calls = append(*fake.calls, "broadcast")
	if prepared != fake.expected {
		return "", errors.New("prepared transaction changed")
	}
	return "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", nil
}

func TestReleasedRoutesAndForbiddenStockPathsMatchFixture(t *testing.T) {
	bytes, err := os.ReadFile("../../tests/fixtures/nipmkt/boltz-client-adapters-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture adapterFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.MappingRevision != MappingRevision {
		t.Fatalf("mapping revision mismatch: %s", fixture.MappingRevision)
	}
	actual := make([]string, 0, len(releasedRouteShapes))
	for _, route := range ReleasedRouteShapes() {
		actual = append(actual, fmt.Sprintf("%s %s", route.Method, route.Path))
	}
	if !reflect.DeepEqual(actual, fixture.Clients.Go.RouteShapes) {
		t.Fatalf("released routes differ from fixture:\nactual: %#v\nfixture: %#v", actual, fixture.Clients.Go.RouteShapes)
	}
	source, err := os.ReadFile("adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range fixture.Clients.Go.ForbiddenSourceTokens {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("adapter source contains stock path %q", forbidden)
		}
	}
}

func TestFundingGateAuthorizesAndPersistsBeforeBroadcast(t *testing.T) {
	calls := []string{}
	prepared := PreparedFunding{RawTransactionHex: "020000000001", OutputIndex: 3}
	gate, err := NewFundingGate(
		validProfile(),
		fakePreparer{calls: &calls, prepared: prepared},
		fakeFinalizer{calls: &calls, approve: validApproval},
		fakeBroadcaster{calls: &calls, expected: prepared},
	)
	if err != nil {
		t.Fatal(err)
	}
	transactionID, err := gate.FundSubmarine(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !validLowerHex32(transactionID) {
		t.Fatalf("invalid transaction ID: %s", transactionID)
	}
	expectedCalls := []string{"prepare", "finalize", "broadcast"}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Fatalf("unexpected call order: %#v", calls)
	}
}

func TestFundingGateRejectsProfilesThatRetainStockPaths(t *testing.T) {
	cases := []Profile{
		{
			ChainPairsDisabled:           true,
			CooperativeEndpointsDisabled: true,
			ProviderWebSocketURL:         "wss://provider.example/v2/ws",
		},
		{
			PartialSignaturesDisabled:    true,
			CooperativeEndpointsDisabled: true,
			ProviderWebSocketURL:         "wss://provider.example/v2/ws",
		},
		{
			PartialSignaturesDisabled: true,
			ChainPairsDisabled:        true,
			ProviderWebSocketURL:      "wss://provider.example/v2/ws",
		},
		{
			PartialSignaturesDisabled:    true,
			ChainPairsDisabled:           true,
			CooperativeEndpointsDisabled: true,
			ProviderWebSocketURL:         "https://relay.example/v2/ws",
		},
	}
	for _, profile := range cases {
		_, err := NewFundingGate(profile, &fakePreparer{}, &fakeFinalizer{}, &fakeBroadcaster{})
		if !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("profile was accepted: %#v", profile)
		}
	}
}

func TestFundingGateNeverBroadcastsWithoutExactBilateralScriptApproval(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*BilateralApproval)
		err    error
	}{
		{
			name: "finalize path",
			mutate: func(approval *BilateralApproval) {
				approval.FinalizePath = "/v2/swap/submarine/changed/finalize"
			},
			err: ErrBilateralApprovalMismatch,
		},
		{
			name: "funding digest",
			mutate: func(approval *BilateralApproval) {
				approval.FundingTransactionSHA256 = strings.Repeat("f", 64)
			},
			err: ErrBilateralApprovalMismatch,
		},
		{
			name: "funding output",
			mutate: func(approval *BilateralApproval) {
				approval.OutputIndex++
			},
			err: ErrBilateralApprovalMismatch,
		},
		{
			name: "provider Contract",
			mutate: func(approval *BilateralApproval) {
				approval.ProviderContractEventID = ""
			},
			err: ErrBilateralApprovalMismatch,
		},
		{
			name: "persisted exit",
			mutate: func(approval *BilateralApproval) {
				approval.ExitPackagePersisted = false
			},
			err: ErrScriptPathExitNotPersisted,
		},
		{
			name: "cooperative exit",
			mutate: func(approval *BilateralApproval) {
				approval.ScriptPathOnly = false
			},
			err: ErrScriptPathExitNotPersisted,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			calls := []string{}
			prepared := PreparedFunding{RawTransactionHex: "020000000001", OutputIndex: 3}
			gate, err := NewFundingGate(
				validProfile(),
				fakePreparer{calls: &calls, prepared: prepared},
				fakeFinalizer{calls: &calls, approve: func(binding FundingBinding) (BilateralApproval, error) {
					approval, approvalErr := validApproval(binding)
					testCase.mutate(&approval)
					return approval, approvalErr
				}},
				fakeBroadcaster{calls: &calls, expected: prepared},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = gate.FundSubmarine(context.Background(), validRequest())
			if !errors.Is(err, testCase.err) {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(calls, []string{"prepare", "finalize"}) {
				t.Fatalf("broadcast was reached: %#v", calls)
			}
		})
	}
}

func validProfile() Profile {
	return Profile{
		PartialSignaturesDisabled:    true,
		ChainPairsDisabled:           true,
		CooperativeEndpointsDisabled: true,
		ProviderWebSocketURL:         "wss://provider.example/v2/ws",
	}
}

func validRequest() FundingRequest {
	return FundingRequest{
		SessionID:  sessionID,
		Address:    "bcrt1qexample",
		AmountSats: 100_000,
	}
}

func validApproval(binding FundingBinding) (BilateralApproval, error) {
	return BilateralApproval{
		SessionID:                binding.SessionID,
		FinalizePath:             binding.FinalizePath,
		FundingTransactionSHA256: binding.FundingTransactionSHA256,
		OutputIndex:              binding.OutputIndex,
		RequesterContractEventID: requesterContractID,
		ProviderContractEventID:  providerContractID,
		ExitPackageSHA256:        exitPackageDigest,
		ExitPackagePersisted:     true,
		ScriptPathOnly:           true,
	}, nil
}
