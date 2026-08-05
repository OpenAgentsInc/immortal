package immortalboltzadapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type processEvent struct {
	ID      string `json:"id"`
	Pubkey  string `json:"pubkey"`
	Kind    int    `json:"kind"`
	Content string `json:"content"`
}

type processSnapshot struct {
	Config struct {
		SessionID string `json:"session_id"`
	} `json:"config"`
	SignedRecords []processEvent           `json:"signed_records"`
	ExitPackages  []map[string]interface{} `json:"exit_packages"`
}

type processAdapterPrepared struct {
	Schema            string `json:"schema"`
	Client            string `json:"client"`
	SessionID         string `json:"session_id"`
	Invoice           string `json:"invoice"`
	RefundPublicKey   string `json:"refund_public_key"`
	RawTransactionHex string `json:"raw_transaction_hex"`
	OutputIndex       uint32 `json:"output_index"`
}

type processAdapterApproval struct {
	Schema                      string `json:"schema"`
	Client                      string `json:"client"`
	SessionID                   string `json:"session_id"`
	FinalizePath                string `json:"finalize_path"`
	FundingTransactionSHA256    string `json:"funding_transaction_sha256"`
	OutputIndex                 uint32 `json:"output_index"`
	RequesterContractEventID    string `json:"requester_contract_event_id"`
	ProviderContractEventID     string `json:"provider_contract_event_id"`
	ExitPackageSHA256           string `json:"exit_package_sha256"`
	ExitPackageMode             string `json:"exit_package_mode"`
	AuthorizationSnapshotSHA256 string `json:"authorization_snapshot_sha256"`
	ExitPackagePersisted        bool   `json:"exit_package_persisted"`
	ScriptPathOnly              bool   `json:"script_path_only"`
}

type processAdapterComplete struct {
	Schema        string `json:"schema"`
	Client        string `json:"client"`
	SessionID     string `json:"session_id"`
	TransactionID string `json:"transaction_id"`
}

type processHTTP struct {
	baseURL string
}

func (client processHTTP) request(method, path string, body interface{}) (map[string]interface{}, error) {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, client.baseURL+path, requestBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Origin", "http://127.0.0.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Client{Timeout: 10 * time.Second}
	response, err := transport.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2_000_129))
	if err != nil {
		return nil, err
	}
	var value map[string]interface{}
	if err := json.Unmarshal(responseBody, &value); err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s returned %s: %v", method, path, response.Status, value)
	}
	return value, nil
}

func readProcessControl(t *testing.T, controlPath string, target interface{}) {
	t.Helper()
	bytes, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, target); err != nil {
		t.Fatal(err)
	}
}

func waitProcessControl(controlPath string, target interface{}) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		bytes, err := os.ReadFile(controlPath)
		if err == nil {
			return json.Unmarshal(bytes, target)
		}
		if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", controlPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func writeProcessControl(controlPath string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(controlPath), ".boltz-control-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			if removeErr := os.Remove(temporaryPath); removeErr != nil && !os.IsNotExist(removeErr) {
				return
			}
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(bytes); err != nil {
		temporary.Close()
		return err
	}
	if syncErr := temporary.Sync(); !processControlSyncAccepted(syncErr) {
		if closeErr := temporary.Close(); closeErr != nil {
			return errors.Join(syncErr, closeErr)
		}
		return syncErr
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, controlPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func processControlSyncAccepted(syncErr error) bool {
	// VirtioFS can report ENOTTY for this polling-only handoff.
	return syncErr == nil || errors.Is(syncErr, syscall.ENOTTY)
}

func TestProcessControlSyncAccepted(t *testing.T) {
	tests := []struct {
		name     string
		syncErr  error
		accepted bool
	}{
		{name: "success", accepted: true},
		{name: "wrapped ENOTTY", syncErr: fmt.Errorf("sync: %w", syscall.ENOTTY), accepted: true},
		{name: "other error", syncErr: syscall.EIO},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if accepted := processControlSyncAccepted(test.syncErr); accepted != test.accepted {
				t.Fatalf("accepted=%t, want %t", accepted, test.accepted)
			}
		})
	}
}

type processFundingPreparer struct {
	transaction string
	outputIndex uint32
}

func (preparer processFundingPreparer) PrepareFunding(context.Context, FundingRequest) (PreparedFunding, error) {
	return PreparedFunding{RawTransactionHex: preparer.transaction, OutputIndex: preparer.outputIndex}, nil
}

type processFinalizer struct {
	client         processHTTP
	stateDirectory string
	clientName     string
}

func (finalizer processFinalizer) FinalizeSubmarineAndPersistExit(
	_ context.Context,
	binding FundingBinding,
) (BilateralApproval, error) {
	request := map[string]interface{}{
		"schema":                     "openagents.immortal.boltz-adapter-finalize.v1",
		"client":                     finalizer.clientName,
		"session_id":                 binding.SessionID,
		"finalize_path":              binding.FinalizePath,
		"raw_transaction_hex":        binding.RawTransactionHex,
		"funding_transaction_sha256": binding.FundingTransactionSHA256,
		"output_index":               binding.OutputIndex,
	}
	if err := writeProcessControl(
		filepath.Join(finalizer.stateDirectory, "boltz-"+finalizer.clientName+"-finalize-request.json"),
		request,
	); err != nil {
		return BilateralApproval{}, err
	}
	var callback processAdapterApproval
	if err := waitProcessControl(
		filepath.Join(finalizer.stateDirectory, "boltz-"+finalizer.clientName+"-approval.json"),
		&callback,
	); err != nil {
		return BilateralApproval{}, err
	}
	if callback.Schema != "openagents.immortal.boltz-adapter-approval.v1" ||
		callback.Client != finalizer.clientName || callback.SessionID != binding.SessionID ||
		callback.FinalizePath != binding.FinalizePath ||
		callback.FundingTransactionSHA256 != binding.FundingTransactionSHA256 ||
		callback.OutputIndex != binding.OutputIndex {
		return BilateralApproval{}, fmt.Errorf("client engine approved another funding binding")
	}
	value, err := finalizer.client.request("POST", binding.FinalizePath, map[string]interface{}{
		"sessionId":                binding.SessionID,
		"finalizePath":             binding.FinalizePath,
		"rawTransactionHex":        binding.RawTransactionHex,
		"fundingTransactionSha256": binding.FundingTransactionSHA256,
		"outputIndex":              binding.OutputIndex,
	})
	if err != nil {
		return BilateralApproval{}, err
	}
	if !providerApprovalMatchesCallback(value, callback) {
		return BilateralApproval{}, fmt.Errorf("provider finalized another client-engine approval")
	}
	return BilateralApproval{
		SessionID:                   stringMember(value, "sessionId"),
		FinalizePath:                stringMember(value, "finalizePath"),
		FundingTransactionSHA256:    stringMember(value, "fundingTransactionSha256"),
		OutputIndex:                 uint32(numberMember(value, "outputIndex")),
		RequesterContractEventID:    stringMember(value, "requesterContractEventId"),
		ProviderContractEventID:     stringMember(value, "providerContractEventId"),
		ExitPackageSHA256:           stringMember(value, "exitPackageSha256"),
		ExitPackageMode:             stringMember(value, "exitPackageMode"),
		AuthorizationSnapshotSHA256: callback.AuthorizationSnapshotSHA256,
		ExitPackagePersisted:        callback.ExitPackagePersisted,
		ScriptPathOnly:              callback.ScriptPathOnly && value["scriptPathOnly"] == true,
	}, nil
}

func providerApprovalMatchesCallback(value map[string]interface{}, callback processAdapterApproval) bool {
	return stringMember(value, "requesterContractEventId") == callback.RequesterContractEventID &&
		stringMember(value, "providerContractEventId") == callback.ProviderContractEventID &&
		stringMember(value, "exitPackageSha256") == callback.ExitPackageSHA256 &&
		stringMember(value, "exitPackageMode") == callback.ExitPackageMode &&
		value["scriptPathOnly"] == callback.ScriptPathOnly
}

func TestProviderFinalizeMustMatchTheClientEngineApproval(t *testing.T) {
	callback := processAdapterApproval{
		RequesterContractEventID: strings.Repeat("1", 64),
		ProviderContractEventID:  strings.Repeat("2", 64),
		ExitPackageSHA256:        strings.Repeat("3", 64),
		ExitPackageMode:          "wallet_sign",
		ScriptPathOnly:           true,
	}
	matching := map[string]interface{}{
		"requesterContractEventId": callback.RequesterContractEventID,
		"providerContractEventId":  callback.ProviderContractEventID,
		"exitPackageSha256":        callback.ExitPackageSHA256,
		"exitPackageMode":          callback.ExitPackageMode,
		"scriptPathOnly":           true,
	}
	if !providerApprovalMatchesCallback(matching, callback) {
		t.Fatal("exact provider approval did not match the client engine callback")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"swapped roles": func(value map[string]interface{}) {
			value["requesterContractEventId"] = callback.ProviderContractEventID
			value["providerContractEventId"] = callback.RequesterContractEventID
		},
		"foreign provider": func(value map[string]interface{}) {
			value["providerContractEventId"] = strings.Repeat("4", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]interface{}, len(matching))
			for key, value := range matching {
				candidate[key] = value
			}
			mutate(candidate)
			if providerApprovalMatchesCallback(candidate, callback) {
				t.Fatal("mismatched provider approval matched the client engine callback")
			}
		})
	}
}

type processBroadcaster struct {
	client         processHTTP
	sessionID      string
	stateDirectory string
	clientName     string
}

func TestAdaptedGoClientFirstBroadcastAgainstProviderProcess(t *testing.T) {
	baseURL := os.Getenv("IMMORTAL_BOLTZ_PROVIDER_PROCESS_URL")
	stateDirectory := os.Getenv("IMMORTAL_BOLTZ_PROVIDER_PROCESS_STATE_DIR")
	if baseURL == "" || stateDirectory == "" {
		t.Skip("provider process first-broadcast gate is not configured")
	}
	submarine := readProcessSnapshot(t, filepath.Join(stateDirectory, "funded-submarine-session.json"))
	bitcoin := processBitcoin(t, processContract(t, submarine), "source")
	raw := stringMember(bitcoin.verifier, "funding_transaction")
	mutated, expectedTransactionID, err := mutateWitnessSameTransactionID(raw)
	if err != nil {
		t.Fatal(err)
	}
	client := processHTTP{baseURL: baseURL}
	body := map[string]interface{}{
		"hex":          raw,
		"mktSessionId": submarine.Config.SessionID,
	}
	first := mustRequest(t, client, "POST", "/v2/chain/BTC/transaction", body)
	if stringMember(first, "id") != expectedTransactionID {
		t.Fatal("first HTTP broadcast returned another transaction ID")
	}
	replay := mustRequest(t, client, "POST", "/v2/chain/BTC/transaction", body)
	if stringMember(replay, "id") != expectedTransactionID {
		t.Fatal("exact first-broadcast replay returned another transaction ID")
	}
	if _, err := client.request("POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          mutated,
		"mktSessionId": submarine.Config.SessionID,
	}); err == nil {
		t.Fatal("same-txid transaction with changed witness was accepted")
	}
	websocketUpdate(t, baseURL, submarine.Config.SessionID, true)
}

func (broadcaster processBroadcaster) BroadcastPreparedFunding(
	_ context.Context,
	prepared PreparedFunding,
) (string, error) {
	value, err := broadcaster.client.request("POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          prepared.RawTransactionHex,
		"mktSessionId": broadcaster.sessionID,
	})
	if err != nil {
		return "", err
	}
	transactionID := stringMember(value, "id")
	if err := writeProcessControl(
		filepath.Join(broadcaster.stateDirectory, "boltz-"+broadcaster.clientName+"-broadcast.json"),
		map[string]interface{}{
			"schema":         "openagents.immortal.boltz-adapter-broadcast.v1",
			"client":         broadcaster.clientName,
			"session_id":     broadcaster.sessionID,
			"transaction_id": transactionID,
		},
	); err != nil {
		return "", err
	}
	var complete processAdapterComplete
	if err := waitProcessControl(
		filepath.Join(broadcaster.stateDirectory, "boltz-"+broadcaster.clientName+"-complete.json"),
		&complete,
	); err != nil {
		return "", err
	}
	if complete.Schema != "openagents.immortal.boltz-adapter-complete.v1" ||
		complete.Client != broadcaster.clientName || complete.SessionID != broadcaster.sessionID ||
		complete.TransactionID != transactionID {
		return "", fmt.Errorf("client engine completed another broadcast")
	}
	return transactionID, nil
}

func TestAdaptedGoClientAgainstProviderProcess(t *testing.T) {
	baseURL := os.Getenv("IMMORTAL_BOLTZ_PROVIDER_PROCESS_URL")
	stateDirectory := os.Getenv("IMMORTAL_BOLTZ_PROVIDER_PROCESS_STATE_DIR")
	if baseURL == "" || stateDirectory == "" {
		t.Skip("provider process gate is not configured")
	}
	if len(ReleasedRouteShapes()) != 13 {
		t.Fatal("released Go route count changed")
	}
	var prepared processAdapterPrepared
	readProcessControl(t, filepath.Join(stateDirectory, "boltz-go-prepared.json"), &prepared)
	if prepared.Schema != "openagents.immortal.boltz-adapter-prepared.v1" ||
		prepared.Client != "go" || !validLowerHex32(prepared.SessionID) {
		t.Fatal("Rust client engine produced another adapter preparation")
	}
	reverse := readProcessSnapshot(t, filepath.Join(stateDirectory, "funded-reverse-session.json"))
	client := processHTTP{baseURL: baseURL}

	version := mustRequest(t, client, "GET", "/v2/version", nil)
	if stringMember(version, "profile") != "bitcoin-lightning-script-path-v1" {
		t.Fatal("provider reported another released profile")
	}
	submarinePairs := mustRequest(t, client, "GET", "/v2/swap/submarine", nil)
	submarinePair := nestedMap(t, submarinePairs, "BTC", "BTC")
	submarineCreate, err := AdaptPinnedSubmarineCreate(PinnedSubmarineCreate{
		From: "BTC", To: "BTC",
		Invoice:         prepared.Invoice,
		PairHash:        stringMember(submarinePair, "hash"),
		RefundPublicKey: prepared.RefundPublicKey,
	}, prepared.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	created := mustRequestEventually(t, client, "POST", "/v2/swap/submarine", submarineCreate)
	mutatedFunding, expectedTransactionID, err := mutateWitnessSameTransactionID(prepared.RawTransactionHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.request("GET", "/v2/chain/BTC/transaction/"+expectedTransactionID, nil); err == nil {
		t.Fatal("prepared funding transaction existed before adapter broadcast")
	}

	gate, err := NewFundingGate(
		Profile{
			PartialSignaturesDisabled:    true,
			ChainPairsDisabled:           true,
			CooperativeEndpointsDisabled: true,
			ProviderWebSocketURL:         strings.Replace(baseURL, "http", "ws", 1) + "/v2/ws",
		},
		processFundingPreparer{
			transaction: prepared.RawTransactionHex,
			outputIndex: prepared.OutputIndex,
		},
		processFinalizer{
			client:         client,
			stateDirectory: stateDirectory,
			clientName:     "go",
		},
		processBroadcaster{
			client: client, sessionID: prepared.SessionID,
			stateDirectory: stateDirectory, clientName: "go",
		},
	)
	if err != nil {
		t.Fatalf("create funding gate: %v", err)
	}
	transactionID, err := gate.FundSubmarine(context.Background(), FundingRequest{
		SessionID:  prepared.SessionID,
		Address:    stringMember(created, "address"),
		AmountSats: uint64(numberMember(created, "expectedAmount")),
	})
	if err != nil {
		t.Fatalf("fund through compatibility gate: %v", err)
	}
	if transactionID != expectedTransactionID {
		t.Fatal("adapter broadcast returned another prepared transaction ID")
	}
	replayedFunding := mustRequest(t, client, "POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          prepared.RawTransactionHex,
		"mktSessionId": prepared.SessionID,
	})
	if stringMember(replayedFunding, "id") != transactionID {
		t.Fatal("exact funding replay returned another transaction")
	}
	if _, err := client.request("POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          mutatedFunding,
		"mktSessionId": prepared.SessionID,
	}); err == nil {
		t.Fatal("same-txid transaction with changed witness was accepted")
	}

	reverseTerms := processContract(t, reverse)
	reverseBitcoin := processBitcoin(t, reverseTerms, "destination")
	reverseRFQ := processProfile(t, oneProcessRecord(t, reverse, 39604))
	reverseConstraints := mapMember(t, reverseRFQ, "constraints")
	reversePairs := mustRequest(t, client, "GET", "/v2/swap/reverse", nil)
	reversePair := nestedMap(t, reversePairs, "BTC", "BTC")
	reverseCreate, err := AdaptPinnedReverseCreate(PinnedReverseCreate{
		From: "BTC", To: "BTC",
		InvoiceAmount:  decimalStringNumber(t, stringMember(reverseConstraints, "input_amount")),
		PreimageHash:   stringMember(reverseConstraints, "payment_hash"),
		ClaimPublicKey: stringMember(reverseBitcoin.leg, "claim_public_key"),
		PairHash:       stringMember(reversePair, "hash"),
	}, reverse.Config.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	mustRequest(t, client, "POST", "/v2/swap/reverse", reverseCreate)
	if _, err := client.request("POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          prepared.RawTransactionHex,
		"mktSessionId": reverse.Config.SessionID,
	}); err == nil {
		t.Fatal("provider accepted a transaction bound to another session")
	}
	reverseClaimID := processStatusTransaction(t, reverse, "requester_claimed")
	reverseClaim := mustRequest(t, client, "GET", "/v2/chain/BTC/transaction/"+reverseClaimID, nil)
	replayedClaim := mustRequest(t, client, "POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          stringMember(reverseClaim, "hex"),
		"mktSessionId": reverse.Config.SessionID,
	})
	if stringMember(replayedClaim, "id") != reverseClaimID {
		t.Fatal("reverse claim replay returned another transaction")
	}

	websocketUpdate(t, baseURL, prepared.SessionID, true)
	submarineTransaction := mustRequest(t, client, "GET", "/v2/swap/submarine/"+prepared.SessionID+"/transaction", nil)
	if stringMember(submarineTransaction, "id") != transactionID {
		t.Fatal("provider transaction route disagrees with broadcast")
	}
	preimage := mustRequest(t, client, "GET", "/v2/swap/submarine/"+prepared.SessionID+"/preimage", nil)
	if !validLowerHex32(stringMember(preimage, "preimage")) {
		t.Fatal("provider returned an invalid released preimage")
	}
	fee := mustRequest(t, client, "GET", "/v2/chain/BTC/fee", nil)
	if numberMember(fee, "fee") <= 0 {
		t.Fatal("provider returned a nonpositive fee")
	}
	height := mustRequest(t, client, "GET", "/v2/chain/BTC/height", nil)
	if numberMember(height, "height") <= 0 {
		t.Fatal("provider returned a nonpositive height")
	}
	transaction := mustRequest(t, client, "GET", "/v2/chain/BTC/transaction/"+transactionID, nil)
	if stringMember(transaction, "hex") != stringMember(submarineTransaction, "hex") {
		t.Fatal("provider public transaction bytes changed")
	}
}

func processStatusTransaction(t *testing.T, snapshot processSnapshot, states ...string) string {
	t.Helper()
	wanted := make(map[string]bool, len(states))
	for _, state := range states {
		wanted[state] = true
	}
	for _, event := range snapshot.SignedRecords {
		if event.Kind != 39607 {
			continue
		}
		profile := processProfile(t, event)
		if wanted[stringMember(profile, "swp_state")] {
			if transactionID, ok := profile["transaction_id"].(string); ok && transactionID != "" {
				return transactionID
			}
		}
	}
	t.Fatal("signed session has no public transaction for the requested states")
	return ""
}

func assertProcessExitPersisted(
	t *testing.T,
	contract map[string]interface{},
	exitPackages []map[string]interface{},
) (string, string) {
	t.Helper()
	commitments, ok := contract["exit_package_commitments"].([]interface{})
	if !ok {
		t.Fatal("contract has no exit package commitments")
	}
	expectedMode := ""
	expectedSHA256 := ""
	for _, value := range commitments {
		commitment, ok := value.(map[string]interface{})
		if !ok || stringMember(commitment, "participant_role") != "requester" || stringMember(commitment, "path") != "refund" {
			continue
		}
		mode := stringMember(commitment, "package_mode")
		if mode != "presigned" && mode != "wallet_sign" {
			continue
		}
		expectedMode = mode
		expectedSHA256 = stringMember(commitment, "package_sha256")
		break
	}
	if expectedMode == "" || !validLowerHex32(expectedSHA256) {
		t.Fatal("contract has no supported requester refund exit commitment")
	}
	for _, exitPackage := range exitPackages {
		document, ok := exitPackage["document"].(map[string]interface{})
		if !ok {
			continue
		}
		exit, ok := document["exit"].(map[string]interface{})
		if !ok || exit["mode"] != expectedMode {
			continue
		}
		digest, err := processExitPackageSHA256(document)
		if err != nil {
			t.Fatal(err)
		}
		if digest == expectedSHA256 {
			return expectedMode, expectedSHA256
		}
	}
	t.Fatal("matching requester refund exit package is not persisted")
	return "", ""
}

func processExitPackageSHA256(document map[string]interface{}) (string, error) {
	commitment := make(map[string]interface{}, len(document))
	for name, value := range document {
		if name != "swap_contract_ids" && name != "contract_sha256" {
			commitment[name] = value
		}
	}
	canonical, err := json.Marshal(commitment)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", digest), nil
}

type processBitcoinTerms struct {
	verifier map[string]interface{}
	leg      map[string]interface{}
}

func readProcessSnapshot(t *testing.T, path string) processSnapshot {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot processSnapshot
	if err := json.Unmarshal(bytes, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func oneProcessRecord(t *testing.T, snapshot processSnapshot, kind int) processEvent {
	t.Helper()
	var match *processEvent
	for index := range snapshot.SignedRecords {
		if snapshot.SignedRecords[index].Kind == kind {
			if match != nil {
				t.Fatalf("kind %d has a fork", kind)
			}
			match = &snapshot.SignedRecords[index]
		}
	}
	if match == nil {
		t.Fatalf("kind %d is missing", kind)
	}
	return *match
}

func processProfile(t *testing.T, event processEvent) map[string]interface{} {
	t.Helper()
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(event.Content), &envelope); err != nil {
		t.Fatal(err)
	}
	return mapMember(t, envelope, "mkt_swp")
}

func processContract(t *testing.T, snapshot processSnapshot) map[string]interface{} {
	t.Helper()
	var contracts []map[string]interface{}
	for _, event := range snapshot.SignedRecords {
		if event.Kind == 39610 {
			contracts = append(contracts, mapMember(t, processProfile(t, event), "contract"))
		}
	}
	if len(contracts) != 2 {
		t.Fatal("bilateral Contracts are missing")
	}
	first, _ := json.Marshal(contracts[0])
	second, _ := json.Marshal(contracts[1])
	if !bytes.Equal(first, second) {
		t.Fatal("bilateral Contracts differ")
	}
	return contracts[0]
}

func processContractIDs(t *testing.T, snapshot processSnapshot) (string, string) {
	t.Helper()
	ids := make(map[string]string)
	for _, event := range snapshot.SignedRecords {
		if event.Kind != 39610 {
			continue
		}
		role := stringMember(processProfile(t, event), "signer_role")
		if role != "requester" && role != "provider" {
			t.Fatalf("unsupported Contract signer role %q", role)
		}
		if ids[role] != "" {
			t.Fatalf("duplicate %s Contract", role)
		}
		ids[role] = event.ID
	}
	if !validLowerHex32(ids["requester"]) || !validLowerHex32(ids["provider"]) {
		t.Fatal("bilateral Contract IDs are missing")
	}
	return ids["requester"], ids["provider"]
}

func processBitcoin(t *testing.T, terms map[string]interface{}, legID string) processBitcoinTerms {
	t.Helper()
	var result processBitcoinTerms
	for _, candidate := range arrayMember(t, terms, "verifier_inputs") {
		value, ok := candidate.(map[string]interface{})
		if ok && stringMember(value, "leg_id") == legID {
			result.verifier = value
		}
	}
	for _, candidate := range arrayMember(t, terms, "legs") {
		value, ok := candidate.(map[string]interface{})
		if ok && stringMember(value, "leg_id") == legID {
			result.leg = value
		}
	}
	if result.verifier == nil || result.leg == nil {
		t.Fatal("Bitcoin terms are missing")
	}
	return result
}

func mustRequest(t *testing.T, client processHTTP, method, path string, body interface{}) map[string]interface{} {
	t.Helper()
	value, err := client.request(method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustRequestEventually(t *testing.T, client processHTTP, method, path string, body interface{}) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		value, err := client.request(method, path, body)
		if err == nil {
			return value
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("request never became ready: %v", lastErr)
	return nil
}

func mapMember(t *testing.T, value map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	member, ok := value[name].(map[string]interface{})
	if !ok {
		t.Fatalf("%s is not an object", name)
	}
	return member
}

func nestedMap(t *testing.T, value map[string]interface{}, names ...string) map[string]interface{} {
	t.Helper()
	for _, name := range names {
		value = mapMember(t, value, name)
	}
	return value
}

func arrayMember(t *testing.T, value map[string]interface{}, name string) []interface{} {
	t.Helper()
	member, ok := value[name].([]interface{})
	if !ok {
		t.Fatalf("%s is not an array", name)
	}
	return member
}

func stringMember(value map[string]interface{}, name string) string {
	member, _ := value[name].(string)
	return member
}

func numberMember(value map[string]interface{}, name string) float64 {
	member, _ := value[name].(float64)
	return member
}

func decimalStringNumber(t *testing.T, value string) uint64 {
	t.Helper()
	var number uint64
	if _, err := fmt.Sscanf(value, "%d", &number); err != nil {
		t.Fatal(err)
	}
	return number
}

func mutateWitnessSameTransactionID(raw string) (string, string, error) {
	transaction, err := hex.DecodeString(raw)
	if err != nil {
		return "", "", fmt.Errorf("decode funding transaction: %w", err)
	}
	if len(transaction) < 10 || transaction[4] != 0 || transaction[5] != 1 {
		return "", "", fmt.Errorf("funding transaction has no SegWit witness")
	}
	offset := 6
	inputCount, inputCountBytes, err := readCompactSize(transaction, offset)
	if err != nil {
		return "", "", err
	}
	stripped := append([]byte{}, transaction[:4]...)
	stripped = append(stripped, transaction[offset:offset+inputCountBytes]...)
	offset += inputCountBytes
	for input := uint64(0); input < inputCount; input++ {
		inputStart := offset
		if offset+36 > len(transaction) {
			return "", "", fmt.Errorf("funding input is truncated")
		}
		offset += 36
		scriptLength, scriptLengthBytes, err := readCompactSize(transaction, offset)
		if err != nil {
			return "", "", err
		}
		offset += scriptLengthBytes
		if scriptLength > uint64(len(transaction)-offset) || offset+int(scriptLength)+4 > len(transaction) {
			return "", "", fmt.Errorf("funding input script is truncated")
		}
		offset += int(scriptLength) + 4
		stripped = append(stripped, transaction[inputStart:offset]...)
	}
	outputCount, outputCountBytes, err := readCompactSize(transaction, offset)
	if err != nil {
		return "", "", err
	}
	outputStart := offset
	offset += outputCountBytes
	for output := uint64(0); output < outputCount; output++ {
		if offset+8 > len(transaction) {
			return "", "", fmt.Errorf("funding output is truncated")
		}
		offset += 8
		scriptLength, scriptLengthBytes, err := readCompactSize(transaction, offset)
		if err != nil {
			return "", "", err
		}
		offset += scriptLengthBytes
		if scriptLength > uint64(len(transaction)-offset) {
			return "", "", fmt.Errorf("funding output script is truncated")
		}
		offset += int(scriptLength)
	}
	stripped = append(stripped, transaction[outputStart:offset]...)
	mutated := append([]byte{}, transaction...)
	mutatedWitness := false
	for input := uint64(0); input < inputCount; input++ {
		itemCount, itemCountBytes, err := readCompactSize(transaction, offset)
		if err != nil {
			return "", "", err
		}
		offset += itemCountBytes
		for item := uint64(0); item < itemCount; item++ {
			itemLength, itemLengthBytes, err := readCompactSize(transaction, offset)
			if err != nil {
				return "", "", err
			}
			offset += itemLengthBytes
			if itemLength > uint64(len(transaction)-offset) {
				return "", "", fmt.Errorf("funding witness is truncated")
			}
			if itemLength > 0 && !mutatedWitness {
				mutated[offset] ^= 1
				mutatedWitness = true
			}
			offset += int(itemLength)
		}
	}
	if !mutatedWitness || offset+4 != len(transaction) {
		return "", "", fmt.Errorf("funding transaction has no mutable bounded witness")
	}
	stripped = append(stripped, transaction[offset:]...)
	first := sha256.Sum256(stripped)
	second := sha256.Sum256(first[:])
	for left, right := 0, len(second)-1; left < right; left, right = left+1, right-1 {
		second[left], second[right] = second[right], second[left]
	}
	return hex.EncodeToString(mutated), hex.EncodeToString(second[:]), nil
}

func readCompactSize(bytes []byte, offset int) (uint64, int, error) {
	if offset >= len(bytes) {
		return 0, 0, fmt.Errorf("compact size is truncated")
	}
	switch bytes[offset] {
	case 0xfd:
		if offset+3 > len(bytes) {
			return 0, 0, fmt.Errorf("compact size uint16 is truncated")
		}
		value := uint64(binary.LittleEndian.Uint16(bytes[offset+1 : offset+3]))
		if value < 0xfd {
			return 0, 0, fmt.Errorf("compact size uint16 is noncanonical")
		}
		return value, 3, nil
	case 0xfe:
		if offset+5 > len(bytes) {
			return 0, 0, fmt.Errorf("compact size uint32 is truncated")
		}
		value := uint64(binary.LittleEndian.Uint32(bytes[offset+1 : offset+5]))
		if value <= 0xffff {
			return 0, 0, fmt.Errorf("compact size uint32 is noncanonical")
		}
		return value, 5, nil
	case 0xff:
		if offset+9 > len(bytes) {
			return 0, 0, fmt.Errorf("compact size uint64 is truncated")
		}
		value := binary.LittleEndian.Uint64(bytes[offset+1 : offset+9])
		if value <= 0xffffffff {
			return 0, 0, fmt.Errorf("compact size uint64 is noncanonical")
		}
		return value, 9, nil
	default:
		return uint64(bytes[offset]), 1, nil
	}
}

func websocketUpdate(t *testing.T, baseURL, sessionID string, proveHeartbeats bool) {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request := fmt.Sprintf("GET /v2/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", parsed.Host, key)
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("WebSocket upgrade failed: %q %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	writeFrame := func(opcode byte, payload []byte) {
		t.Helper()
		mask := make([]byte, 4)
		if _, err := rand.Read(mask); err != nil {
			t.Fatal(err)
		}
		frame := []byte{0x80 | opcode}
		if len(payload) <= 125 {
			frame = append(frame, byte(len(payload))|0x80)
		} else {
			frame = append(frame, 126|0x80, byte(len(payload)>>8), byte(len(payload)))
		}
		frame = append(frame, mask...)
		for index, value := range payload {
			frame = append(frame, value^mask[index%4])
		}
		if _, err := connection.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	readFrame := func() (byte, []byte) {
		t.Helper()
		first, err := reader.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		second, err := reader.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		length := int(second & 0x7f)
		if length == 126 {
			var extended [2]byte
			if _, err := io.ReadFull(reader, extended[:]); err != nil {
				t.Fatal(err)
			}
			length = int(binary.BigEndian.Uint16(extended[:]))
		}
		message := make([]byte, length)
		if _, err := io.ReadFull(reader, message); err != nil {
			t.Fatal(err)
		}
		return first & 0x0f, message
	}
	if err := connection.SetReadDeadline(time.Now().Add(45 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if proveHeartbeats {
		time.Sleep(15 * time.Second)
		writeFrame(1, []byte(`{"op":"ping"}`))
		opcode, message := readFrame()
		if opcode != 1 || string(message) != `{"event":"pong"}` {
			t.Fatalf("application heartbeat response changed: opcode=%d payload=%q", opcode, message)
		}
		time.Sleep(16 * time.Second)
		writeFrame(9, nil)
		opcode, message = readFrame()
		if opcode != 10 || len(message) != 0 {
			t.Fatalf("control heartbeat response changed: opcode=%d payload=%q", opcode, message)
		}
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"op": "subscribe", "channel": "swap.update", "args": []string{sessionID},
	})
	writeFrame(1, payload)
	for {
		opcode, message := readFrame()
		if opcode != 1 {
			continue
		}
		var value map[string]interface{}
		if err := json.Unmarshal(message, &value); err != nil {
			t.Fatal(err)
		}
		if stringMember(value, "event") == "update" {
			return
		}
	}
}
