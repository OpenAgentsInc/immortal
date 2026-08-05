#[allow(dead_code)]
#[path = "../src/bitcoind.rs"]
mod bitcoind;
#[allow(dead_code)]
#[path = "../src/cln.rs"]
mod cln;

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use bitcoind::{
    BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindError, BitcoindLimits, Freshness,
    FreshnessPolicy, PollBackoff, RpcRequestId,
};
use cln::{ClnClient, ClnEndpoint, ClnError, ClnLimits, ClnRequestId, Millisatoshi};
use immortal_core::mkt_swp_verify::parse_bolt11;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    task::JoinHandle,
};

static SOCKET_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn bitcoind_binds_request_id_and_basic_auth_without_leaking_credentials() {
    let body = json!({
        "result":"11".repeat(32),
        "error":null,
        "id":"effect:chain-tip:7"
    })
    .to_string();
    let (endpoint, server) = spawn_bitcoind(http_response(200, &body)).await;
    let auth = BitcoindAuth::new("rpc-user", "top-secret").unwrap();
    let client = BitcoindClient::new(endpoint, auth.clone(), BitcoindLimits::default()).unwrap();
    let request_id = RpcRequestId::new("effect:chain-tip:7").unwrap();
    assert_eq!(
        client.best_block_hash(&request_id).await.unwrap(),
        "11".repeat(32)
    );

    let request = server.await.unwrap();
    assert!(request.contains("Authorization: Basic cnBjLXVzZXI6dG9wLXNlY3JldA==\r\n"));
    let request: Value = serde_json::from_slice(http_body(request.as_bytes())).unwrap();
    assert_eq!(request["id"], "effect:chain-tip:7");
    assert_eq!(request["method"], "getbestblockhash");
    assert!(!format!("{auth:?}").contains("top-secret"));
    assert!(!format!("{client:?}").contains("top-secret"));
}

#[tokio::test]
async fn bitcoind_requests_conservative_fee_estimate_and_rounds_up()
-> Result<(), Box<dyn std::error::Error>> {
    let body = json!({
        "result":{"feerate":0.00001001,"blocks":2},
        "error":null,
        "id":"quote:feerate:1"
    })
    .to_string();
    let (endpoint, server) = spawn_bitcoind(http_response(200, &body)).await;
    let client = BitcoindClient::new(
        endpoint,
        BitcoindAuth::new("rpc-user", "top-secret")?,
        BitcoindLimits::default(),
    )?;
    let request_id = RpcRequestId::new("quote:feerate:1")?;
    assert_eq!(
        client
            .estimated_feerate_sat_per_vbyte(&request_id, 2)
            .await?,
        Some(2)
    );
    let request = server.await?;
    let request: Value = serde_json::from_slice(http_body(request.as_bytes()))?;
    assert_eq!(request["method"], "estimatesmartfee");
    assert_eq!(request["params"], json!([2, "conservative"]));
    Ok(())
}

#[tokio::test]
async fn bitcoind_rejects_wrong_id_rpc_errors_truncation_and_ambiguous_framing() {
    let cases = [
        (
            http_response(
                200,
                &json!({"result":null,"error":null,"id":"other"}).to_string(),
            ),
            BitcoindError::WrongResponseId,
        ),
        (
            http_response(
                200,
                &json!({
                    "result":null,
                    "error":{"code":-5,"message":"top-secret raw transaction"},
                    "id":"effect:test:1"
                })
                .to_string(),
            ),
            BitcoindError::Rpc { code: -5 },
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{".to_vec(),
            BitcoindError::Protocol("truncated response body"),
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            BitcoindError::Protocol("ambiguous Content-Length header"),
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
            BitcoindError::Protocol("Transfer-Encoding responses are unsupported"),
        ),
        (
            http_response(
                500,
                &json!({"result":null,"error":null,"id":"effect:test:1"}).to_string(),
            ),
            BitcoindError::HttpStatus(500),
        ),
    ];
    for (response, expected) in cases {
        let (endpoint, server) = spawn_bitcoind(response).await;
        let client = bitcoind_client(endpoint, BitcoindLimits::default());
        let error = client
            .call(
                &RpcRequestId::new("effect:test:1").unwrap(),
                "getrawmempool",
                json!([]),
            )
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("top-secret"));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn bitcoind_applies_one_bounded_timeout_to_the_response() {
    let body = json!({"result":[],"error":null,"id":"effect:timeout:1"}).to_string();
    let (endpoint, server) =
        spawn_bitcoind_delayed(http_response(200, &body), Duration::from_millis(50)).await;
    let limits = BitcoindLimits {
        io_timeout: Duration::from_millis(10),
        ..BitcoindLimits::default()
    };
    let error = bitcoind_client(endpoint, limits)
        .call(
            &RpcRequestId::new("effect:timeout:1").unwrap(),
            "getrawmempool",
            json!([]),
        )
        .await
        .unwrap_err();
    assert_eq!(error, BitcoindError::TimedOut("response read"));
    server.await.unwrap();
}

#[tokio::test]
async fn bitcoind_refuses_non_loopback_and_oversized_responses() {
    let client = bitcoind_client(
        BitcoindEndpoint::new("192.0.2.1", 8332).unwrap(),
        BitcoindLimits::default(),
    );
    assert_eq!(
        client
            .call(
                &RpcRequestId::new("effect:offbox:1").unwrap(),
                "getbestblockhash",
                json!([]),
            )
            .await
            .unwrap_err(),
        BitcoindError::NonLoopbackEndpoint
    );

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n".to_vec();
    let (endpoint, server) = spawn_bitcoind(response).await;
    let limits = BitcoindLimits {
        max_response_bytes: 1024,
        ..BitcoindLimits::default()
    };
    let error = bitcoind_client(endpoint, limits)
        .call(
            &RpcRequestId::new("effect:oversize:1").unwrap(),
            "getbestblockhash",
            json!([]),
        )
        .await
        .unwrap_err();
    assert_eq!(error, BitcoindError::Protocol("response body is too large"));
    server.await.unwrap();
}

#[test]
fn bitcoind_freshness_and_poll_backoff_are_bounded() {
    let freshness = FreshnessPolicy::new(Duration::from_secs(10)).unwrap();
    assert_eq!(
        freshness.evaluate(Duration::from_secs(5), Duration::from_secs(15)),
        Freshness::Fresh
    );
    assert_eq!(
        freshness.evaluate(Duration::from_secs(5), Duration::from_secs(16)),
        Freshness::Stale
    );
    assert_eq!(
        freshness.evaluate(Duration::from_secs(6), Duration::from_secs(5)),
        Freshness::ClockRegression
    );

    let mut backoff = PollBackoff::new(Duration::from_secs(1), Duration::from_secs(4), 3).unwrap();
    assert_eq!(backoff.record_failure(), Some(Duration::from_secs(1)));
    assert_eq!(backoff.record_failure(), Some(Duration::from_secs(2)));
    assert_eq!(backoff.record_failure(), Some(Duration::from_secs(4)));
    assert_eq!(backoff.record_failure(), None);
    backoff.record_success();
    assert_eq!(backoff.consecutive_failures(), 0);
    assert_eq!(backoff.record_failure(), Some(Duration::from_secs(1)));
}

#[tokio::test]
async fn cln_uses_exact_msat_and_binds_invoice_response_and_replay_id() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-client-engine-v1.json"
    ))
    .unwrap();
    let deterministic = &fixture["deterministic_session"];
    let invoice_string = deterministic["invoice"].as_str().unwrap();
    let payment_hash = deterministic["payment_hash"].as_str().unwrap();
    let expires_at = deterministic["invoice_timestamp"].as_u64().unwrap()
        + deterministic["invoice_expiry_seconds"].as_u64().unwrap();
    let path = socket_path("cln-invoice");
    let responses = vec![
        json!({
            "jsonrpc":"2.0",
            "id":"effect:invoice:4",
            "result":{
                "bolt11":invoice_string,
                "payment_hash":payment_hash,
                "expires_at":expires_at
            }
        }),
        json!({
            "jsonrpc":"2.0",
            "id":"effect:invoice:4",
            "result":{"invoices":[]}
        }),
    ];
    let server = spawn_cln(path.clone(), responses).await;
    let client = cln_client(&path, ClnLimits::default());
    let request_id = ClnRequestId::new("effect:invoice:4").unwrap();
    let invoice = client
        .invoice(
            &request_id,
            Millisatoshi::from_satoshis(1_000).unwrap(),
            "swap-order-4",
            "swap invoice",
            604_800,
        )
        .await
        .unwrap();
    assert_eq!(invoice.payment_hash, payment_hash);
    client
        .list_invoices(&request_id, Some("swap-order-4"))
        .await
        .unwrap();

    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["id"], "effect:invoice:4");
    assert_eq!(requests[1]["id"], "effect:invoice:4");
    assert_eq!(requests[0]["params"]["amount_msat"], "1000000msat");
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_rejects_wrong_id_rpc_errors_truncation_and_oversize() {
    let cases = [
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":\"other\",\"result\":{}}\n".to_vec(),
            ClnError::WrongResponseId,
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":\"effect:test:2\",\"error\":{\"code\":-32601,\"message\":\"secret preimage\"}}\n".to_vec(),
            ClnError::Rpc { code: -32601 },
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":\"effect:test:2\"}".to_vec(),
            ClnError::Protocol("truncated response without newline"),
        ),
    ];
    for (index, (response, expected)) in cases.into_iter().enumerate() {
        let path = socket_path(&format!("cln-error-{index}"));
        let server = spawn_cln_bytes(path.clone(), vec![response]).await;
        let client = cln_client(&path, ClnLimits::default());
        let error = client
            .call(
                &ClnRequestId::new("effect:test:2").unwrap(),
                "listpays",
                json!({}),
            )
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("secret preimage"));
        server.await.unwrap();
        cleanup_socket(&path);
    }

    let path = socket_path("cln-oversize");
    let server = spawn_cln_bytes(path.clone(), vec![vec![b'x'; 1025]]).await;
    let limits = ClnLimits {
        max_response_bytes: 1024,
        ..ClnLimits::default()
    };
    let error = cln_client(&path, limits)
        .call(
            &ClnRequestId::new("effect:test:2").unwrap(),
            "listpays",
            json!({}),
        )
        .await
        .unwrap_err();
    assert_eq!(error, ClnError::Protocol("response exceeds byte limit"));
    server.await.unwrap();
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_capability_probe_fails_closed_when_hold_plugin_is_missing() {
    let path = socket_path("cln-capability");
    let server = spawn_cln(
        path.clone(),
        vec![json!({
            "jsonrpc":"2.0",
            "id":"startup:probe:0",
            "result":{"help":[]}
        })],
    )
    .await;
    let error = cln_client(&path, ClnLimits::default())
        .probe_required_capabilities("startup")
        .await
        .unwrap_err();
    assert_eq!(error, ClnError::MissingCapability("holdinvoice"));
    let requests = server.await.unwrap();
    assert_eq!(requests[0]["method"], "help");
    assert_eq!(requests[0]["params"]["command"], "holdinvoice");
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_capability_probe_checks_every_required_method_on_fresh_connections() {
    let methods = [
        "holdinvoice",
        "listholdinvoices",
        "settleholdinvoice",
        "cancelholdinvoice",
        "invoice",
        "pay",
        "listinvoices",
        "listpays",
        "listfunds",
        "getinfo",
    ];
    let responses = methods
        .iter()
        .enumerate()
        .map(|(index, method)| {
            json!({
                "jsonrpc":"2.0",
                "id":format!("startup:probe:{index}"),
                "result":{"help":[{"command":format!("{method} usage")}]}
            })
        })
        .collect();
    let path = socket_path("cln-capability-complete");
    let server = spawn_cln(path.clone(), responses).await;
    let capabilities = cln_client(&path, ClnLimits::default())
        .probe_required_capabilities("startup")
        .await
        .unwrap();
    assert!(capabilities.hold_plugin);
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), methods.len());
    for (request, method) in requests.iter().zip(methods) {
        assert_eq!(request["method"], "help");
        assert_eq!(request["params"]["command"], method);
    }
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_block_height_binds_getinfo_and_rejects_out_of_range_values() {
    let cases = [
        (
            json!({"blockheight": 321, "network":"regtest"}),
            Ok(cln::ClnNodeInfo {
                block_height: 321,
                network: "regtest".to_owned(),
            }),
        ),
        (
            json!({"blockheight": u64::from(u32::MAX) + 1, "network":"regtest"}),
            Err(ClnError::Json("CLN blockheight exceeds v1")),
        ),
        (
            json!({"blockheight": "321", "network":"regtest"}),
            Err(ClnError::Json("getinfo result has no blockheight")),
        ),
        (
            json!({"blockheight": 321, "network":"regtest", "warning_bitcoind_sync":"still syncing"}),
            Err(ClnError::Unsynced("bitcoind")),
        ),
        (
            json!({"blockheight": 321, "network":"regtest", "warning_lightningd_sync":"still syncing"}),
            Err(ClnError::Unsynced("lightningd")),
        ),
        (
            json!({"blockheight": 321, "network":"REGTEST"}),
            Err(ClnError::Json("getinfo result has no valid network")),
        ),
    ];
    for (index, (result, expected)) in cases.into_iter().enumerate() {
        let request_id = format!("quote-height:{index}");
        let path = socket_path(&format!("cln-height-{index}"));
        let server = spawn_cln(
            path.clone(),
            vec![json!({"jsonrpc":"2.0","id":request_id,"result":result})],
        )
        .await;
        let observed = cln_client(&path, ClnLimits::default())
            .node_info(&ClnRequestId::new(request_id).unwrap())
            .await;
        assert_eq!(observed, expected);
        let requests = server.await.unwrap();
        assert_eq!(requests[0]["method"], "getinfo");
        assert_eq!(requests[0]["params"], json!({}));
        cleanup_socket(&path);
    }
}

#[tokio::test]
async fn cln_hold_invoice_matches_the_pinned_plugin_wire() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-client-engine-v1.json"
    ))
    .unwrap();
    let bolt11 = fixture["deterministic_session"]["invoice"]
        .as_str()
        .unwrap();
    let parsed = parse_bolt11(bolt11).unwrap();
    let payment_hash = parsed
        .payment_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let amount = Millisatoshi::from_millisatoshis(parsed.amount_msat.unwrap());
    let path = socket_path("cln-hold-wire");
    let server = spawn_cln(
        path.clone(),
        vec![json!({
            "jsonrpc":"2.0",
            "id":"effect:hold:1",
            "result":{"bolt11":bolt11}
        })],
    )
    .await;
    let invoice = cln_client(&path, ClnLimits::default())
        .hold_invoice(
            &ClnRequestId::new("effect:hold:1").unwrap(),
            &payment_hash,
            amount,
        )
        .await
        .unwrap();
    assert_eq!(invoice.payment_hash, payment_hash);
    assert_eq!(invoice.bolt11, bolt11);
    assert_eq!(invoice.expires_at, parsed.timestamp + parsed.expiry_seconds);
    let requests = server.await.unwrap();
    assert_eq!(requests[0]["method"], "holdinvoice");
    assert_eq!(
        requests[0]["params"],
        json!({
            "payment_hash":payment_hash,
            "amount":amount.as_millisatoshis()
        })
    );
    cleanup_socket(&path);
}

#[test]
fn cln_debug_output_redacts_the_socket_path() {
    let path = socket_path("cln-private-path");
    let endpoint = ClnEndpoint::new(path.clone()).unwrap();
    let client = ClnClient::new(endpoint.clone(), ClnLimits::default()).unwrap();
    assert!(!format!("{endpoint:?}").contains(path.to_string_lossy().as_ref()));
    assert!(!format!("{client:?}").contains(path.to_string_lossy().as_ref()));
}

#[tokio::test]
async fn cln_hold_settle_and_cancel_match_the_pinned_plugin_wire() {
    let path = socket_path("cln-hold-terminal-wire");
    let server = spawn_cln(
        path.clone(),
        vec![
            json!({
                "jsonrpc":"2.0",
                "id":"effect:settle:1",
                "result":{}
            }),
            json!({
                "jsonrpc":"2.0",
                "id":"effect:cancel:1",
                "result":{}
            }),
        ],
    )
    .await;
    let client = cln_client(&path, ClnLimits::default());
    let preimage = "11".repeat(32);
    client
        .settle_hold_invoice(&ClnRequestId::new("effect:settle:1").unwrap(), &preimage)
        .await
        .unwrap();
    let payment_hash = "22".repeat(32);
    client
        .cancel_hold_invoice(
            &ClnRequestId::new("effect:cancel:1").unwrap(),
            &payment_hash,
        )
        .await
        .unwrap();
    let requests = server.await.unwrap();
    assert_eq!(requests[0]["method"], "settleholdinvoice");
    assert_eq!(requests[0]["params"], json!({"preimage":preimage}));
    assert_eq!(requests[1]["method"], "cancelholdinvoice");
    assert_eq!(requests[1]["params"], json!({"payment_hash":payment_hash}));
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_pay_rejects_a_result_not_bound_to_the_requested_invoice() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-client-engine-v1.json"
    ))
    .unwrap();
    let invoice = fixture["deterministic_session"]["invoice"]
        .as_str()
        .unwrap();
    let path = socket_path("cln-pay-binding");
    let server = spawn_cln(
        path.clone(),
        vec![json!({
            "jsonrpc":"2.0",
            "id":"effect:pay:9",
            "result":{
                "payment_hash":"33".repeat(32),
                "status":"complete",
                "amount_msat":"1000000msat",
                "amount_sent_msat":"1001000msat"
            }
        })],
    )
    .await;
    let error = cln_client(&path, ClnLimits::default())
        .pay(
            &ClnRequestId::new("effect:pay:9").unwrap(),
            invoice,
            Some(Millisatoshi::from_satoshis(2).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ClnError::Json("payment result does not bind the requested invoice")
    );
    let requests = server.await.unwrap();
    assert_eq!(requests[0]["id"], "effect:pay:9");
    assert_eq!(requests[0]["params"]["maxfee"], "2000msat");
    cleanup_socket(&path);
}

#[test]
fn cln_satoshi_conversion_is_exact_and_overflow_checked() {
    let amount = Millisatoshi::from_satoshis(42).unwrap();
    assert_eq!(amount.as_millisatoshis(), 42_000);
    assert_eq!(amount.to_satoshis_exact().unwrap(), 42);
    assert_eq!(
        Millisatoshi::from_millisatoshis(42_001)
            .to_satoshis_exact()
            .unwrap_err(),
        ClnError::InexactSatoshiAmount
    );
    assert_eq!(
        Millisatoshi::from_satoshis(u64::MAX).unwrap_err(),
        ClnError::AmountOverflow
    );
    assert_eq!(
        Millisatoshi::parse(&json!("001000msat")).unwrap_err(),
        ClnError::Json("millisatoshi amount has invalid shape")
    );
}

fn bitcoind_client(endpoint: BitcoindEndpoint, limits: BitcoindLimits) -> BitcoindClient {
    BitcoindClient::new(
        endpoint,
        BitcoindAuth::new("user", "password").unwrap(),
        limits,
    )
    .unwrap()
}

async fn spawn_bitcoind(response: Vec<u8>) -> (BitcoindEndpoint, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
        request
    });
    (
        BitcoindEndpoint::new("127.0.0.1", address.port()).unwrap(),
        server,
    )
}

async fn spawn_bitcoind_delayed(
    response: Vec<u8>,
    delay: Duration,
) -> (BitcoindEndpoint, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request(&mut stream).await;
        tokio::time::sleep(delay).await;
        match stream.write_all(&response).await {
            Ok(()) => {
                stream.shutdown().await.unwrap();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) => {}
            Err(error) => panic!("delayed bitcoind fixture write failed: {error}"),
        }
    });
    (
        BitcoindEndpoint::new("127.0.0.1", address.port()).unwrap(),
        server,
    )
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let body_start = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&request[..body_start]).unwrap();
    let content_length = head
        .split("\r\n")
        .find_map(|line| {
            line.strip_prefix("Content-Length: ")
                .and_then(|length| length.parse::<usize>().ok())
        })
        .unwrap();
    while request.len() - body_start < content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(request).unwrap()
}

fn http_body(request: &[u8]) -> &[u8] {
    let start = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[start..]
}

fn http_response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn cln_client(path: &Path, limits: ClnLimits) -> ClnClient {
    ClnClient::new(ClnEndpoint::new(path.to_path_buf()).unwrap(), limits).unwrap()
}

async fn spawn_cln(path: PathBuf, responses: Vec<Value>) -> JoinHandle<Vec<Value>> {
    spawn_cln_bytes(
        path,
        responses
            .into_iter()
            .map(|response| {
                let mut bytes = serde_json::to_vec(&response).unwrap();
                bytes.push(b'\n');
                bytes
            })
            .collect(),
    )
    .await
}

async fn spawn_cln_bytes(path: PathBuf, responses: Vec<Vec<u8>>) -> JoinHandle<Vec<Value>> {
    cleanup_socket(&path);
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests.push(read_cln_request(&mut stream).await);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        requests
    })
}

async fn read_cln_request(stream: &mut UnixStream) -> Value {
    let mut request = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        if byte[0] == b'\n' {
            break;
        }
        request.push(byte[0]);
    }
    serde_json::from_slice(&request).unwrap()
}

fn socket_path(name: &str) -> PathBuf {
    let sequence = SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "immortal-provider-{name}-{}-{sequence}.sock",
        std::process::id()
    ))
}

fn cleanup_socket(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to remove test socket: {error}"),
    }
}
