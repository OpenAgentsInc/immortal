package immortalboltzadapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

type processFundingPreparer struct {
	transaction string
	outputIndex uint32
}

func (preparer processFundingPreparer) PrepareFunding(context.Context, FundingRequest) (PreparedFunding, error) {
	return PreparedFunding{RawTransactionHex: preparer.transaction, OutputIndex: preparer.outputIndex}, nil
}

type processFinalizer struct {
	client            processHTTP
	exitPackageSHA256 string
	exitPackageMode   string
}

func (finalizer processFinalizer) FinalizeSubmarineAndPersistExit(
	_ context.Context,
	binding FundingBinding,
) (BilateralApproval, error) {
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
	if stringMember(value, "exitPackageSha256") != finalizer.exitPackageSHA256 ||
		stringMember(value, "exitPackageMode") != finalizer.exitPackageMode {
		return BilateralApproval{}, fmt.Errorf("provider finalized another persisted exit package")
	}
	return BilateralApproval{
		SessionID:                stringMember(value, "sessionId"),
		FinalizePath:             stringMember(value, "finalizePath"),
		FundingTransactionSHA256: stringMember(value, "fundingTransactionSha256"),
		OutputIndex:              uint32(numberMember(value, "outputIndex")),
		RequesterContractEventID: stringMember(value, "requesterContractEventId"),
		ProviderContractEventID:  stringMember(value, "providerContractEventId"),
		ExitPackageSHA256:        stringMember(value, "exitPackageSha256"),
		ExitPackageMode:          stringMember(value, "exitPackageMode"),
		ExitPackagePersisted:     true,
		ScriptPathOnly:           value["scriptPathOnly"] == true,
	}, nil
}

type processBroadcaster struct {
	client    processHTTP
	sessionID string
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
	return stringMember(value, "id"), nil
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
	submarine := readProcessSnapshot(t, filepath.Join(stateDirectory, "funded-submarine-session.json"))
	reverse := readProcessSnapshot(t, filepath.Join(stateDirectory, "funded-reverse-session.json"))
	client := processHTTP{baseURL: baseURL}

	version := mustRequest(t, client, "GET", "/v2/version", nil)
	if stringMember(version, "profile") != "bitcoin-lightning-script-path-v1" {
		t.Fatal("provider reported another released profile")
	}
	submarineTerms := processContract(t, submarine)
	submarineBitcoin := processBitcoin(t, submarineTerms, "source")
	exitPackageMode, exitPackageSHA256 := assertProcessExitPersisted(
		t,
		submarineTerms,
		submarine.ExitPackages,
	)
	submarineRFQ := processProfile(t, oneProcessRecord(t, submarine, 39604))
	submarinePairs := mustRequest(t, client, "GET", "/v2/swap/submarine", nil)
	submarinePair := nestedMap(t, submarinePairs, "BTC", "BTC")
	created := mustRequest(t, client, "POST", "/v2/swap/submarine", map[string]interface{}{
		"from":            "BTC",
		"to":              "BTC",
		"invoice":         stringMember(submarineRFQ, "invoice"),
		"pairHash":        stringMember(submarinePair, "hash"),
		"refundPublicKey": stringMember(submarineBitcoin.leg, "refund_public_key"),
		"mktSessionId":    submarine.Config.SessionID,
	})

	outputIndex := uint32(numberMember(submarineBitcoin.verifier, "output_index"))
	gate, err := NewFundingGate(
		Profile{
			PartialSignaturesDisabled:    true,
			ChainPairsDisabled:           true,
			CooperativeEndpointsDisabled: true,
			ProviderWebSocketURL:         strings.Replace(baseURL, "http", "ws", 1) + "/v2/ws",
		},
		processFundingPreparer{
			transaction: stringMember(submarineBitcoin.verifier, "funding_transaction"),
			outputIndex: outputIndex,
		},
		processFinalizer{
			client:            client,
			exitPackageSHA256: exitPackageSHA256,
			exitPackageMode:   exitPackageMode,
		},
		processBroadcaster{client: client, sessionID: submarine.Config.SessionID},
	)
	if err != nil {
		t.Fatalf("create funding gate: %v", err)
	}
	transactionID, err := gate.FundSubmarine(context.Background(), FundingRequest{
		SessionID:  submarine.Config.SessionID,
		Address:    stringMember(created, "address"),
		AmountSats: uint64(numberMember(created, "expectedAmount")),
	})
	if err != nil {
		t.Fatalf("fund through compatibility gate: %v", err)
	}
	replayedFunding := mustRequest(t, client, "POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          stringMember(submarineBitcoin.verifier, "funding_transaction"),
		"mktSessionId": submarine.Config.SessionID,
	})
	if stringMember(replayedFunding, "id") != transactionID {
		t.Fatal("exact funding replay returned another transaction")
	}

	reverseTerms := processContract(t, reverse)
	reverseBitcoin := processBitcoin(t, reverseTerms, "destination")
	reverseRFQ := processProfile(t, oneProcessRecord(t, reverse, 39604))
	reverseConstraints := mapMember(t, reverseRFQ, "constraints")
	reversePairs := mustRequest(t, client, "GET", "/v2/swap/reverse", nil)
	reversePair := nestedMap(t, reversePairs, "BTC", "BTC")
	mustRequest(t, client, "POST", "/v2/swap/reverse", map[string]interface{}{
		"from":           "BTC",
		"to":             "BTC",
		"invoiceAmount":  decimalStringNumber(t, stringMember(reverseConstraints, "input_amount")),
		"preimageHash":   stringMember(reverseConstraints, "payment_hash"),
		"claimPublicKey": stringMember(reverseBitcoin.leg, "claim_public_key"),
		"pairHash":       stringMember(reversePair, "hash"),
		"mktSessionId":   reverse.Config.SessionID,
	})
	if _, err := client.request("POST", "/v2/chain/BTC/transaction", map[string]interface{}{
		"hex":          stringMember(submarineBitcoin.verifier, "funding_transaction"),
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

	websocketUpdate(t, baseURL, submarine.Config.SessionID)
	submarineTransaction := mustRequest(t, client, "GET", "/v2/swap/submarine/"+submarine.Config.SessionID+"/transaction", nil)
	if stringMember(submarineTransaction, "id") != transactionID {
		t.Fatal("provider transaction route disagrees with broadcast")
	}
	preimage := mustRequest(t, client, "GET", "/v2/swap/submarine/"+submarine.Config.SessionID+"/preimage", nil)
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

func websocketUpdate(t *testing.T, baseURL, sessionID string) {
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
	payload, _ := json.Marshal(map[string]interface{}{
		"op": "subscribe", "channel": "swap.update", "args": []string{sessionID},
	})
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		t.Fatal(err)
	}
	frame := []byte{0x81}
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
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
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
		if first&0x0f != 1 {
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
