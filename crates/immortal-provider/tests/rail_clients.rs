#[allow(dead_code)]
#[path = "../src/bitcoind.rs"]
mod bitcoind;
#[allow(dead_code)]
#[path = "../src/cln.rs"]
mod cln;
#[allow(dead_code)]
#[path = "../src/elementsd.rs"]
mod elementsd;
#[allow(dead_code)]
#[path = "../src/lightning.rs"]
mod lightning;
#[cfg(feature = "lnd")]
#[allow(dead_code)]
#[path = "../src/lnd.rs"]
mod lnd;

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use bitcoind::{
    BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindError, BitcoindLimits, Freshness,
    FreshnessPolicy, PollBackoff, RpcRequestId,
};
use cln::{
    ClnClient, ClnEndpoint, ClnError, ClnLimits, ClnRequestId, IMMORTAL_REGTEST_HOLD_METHOD,
    Millisatoshi,
};
use elementsd::{ElementsdClient, ElementsdError, ElementsdMempoolAdmission, ElementsdWalletName};
use immortal_core::liquid::{LiquidAssetId, LiquidNetworkId};
use immortal_core::mkt_swp_verify::parse_bolt11;
use lightning::{ClnLightningRail, LightningRail};
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
            http_response(
                500,
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

#[tokio::test]
async fn elementsd_binds_network_wallet_unblind_and_mempool_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/liquid-rail-v1.json"
    ))?;
    let network = &fixture["network"];
    let vector = &fixture["parser_vectors"][0];
    assert_eq!(
        fixture["rpc_normalization"],
        json!({
            "mempool_transaction_missing_confirmations":"zero",
            "confirmed_transaction_missing_confirmations":"reject",
            "non_numeric_confirmations":"reject",
            "positive_confirmations_without_blockhash":"reject",
            "zero_confirmations_with_blockhash":"reject"
        })
    );
    let responses = vec![
        http_response(
            200,
            &json!({
                "result":network["genesis_hash"],
                "error":null,
                "id":"liquid:probe:genesis"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"pegged_asset":network["pegged_asset"]},
                "error":null,
                "id":"liquid:probe:sidechain"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"bestblockhash":"22".repeat(32),"blocks":42},
                "error":null,
                "id":"liquid:probe:tip"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"hex":vector["trusted_local_unblind"],"complete":true},
                "error":null,
                "id":"liquid:unblind:1"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":[{"txid":"33".repeat(32),"allowed":true}],
                "error":null,
                "id":"liquid:mempool:1"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{
                    "hex":vector["raw_transaction"],
                    "confirmations":2,
                    "blockhash":"44".repeat(32)
                },
                "error":null,
                "id":"liquid:observe:transaction"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"bestblock":"44".repeat(32)},
                "error":null,
                "id":"liquid:observe:unspent"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"hex":vector["raw_transaction"]},
                "error":null,
                "id":"liquid:observe:mempool"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"hex":vector["raw_transaction"],"confirmations":"0"},
                "error":null,
                "id":"liquid:observe:malformed"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"hex":vector["raw_transaction"],"confirmations":2},
                "error":null,
                "id":"liquid:observe:missing-blockhash"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{
                    "hex":vector["raw_transaction"],
                    "confirmations":0,
                    "blockhash":"77".repeat(32)
                },
                "error":null,
                "id":"liquid:observe:zero-confirmed"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse(network["network_id"].as_str().ok_or("network ID")?)?,
        LiquidAssetId::parse(network["pegged_asset"].as_str().ok_or("pegged asset")?)?,
    )?;
    let view = client.probe("liquid:probe").await?;
    assert_eq!(view.height, 42);
    let raw = decode_fixture_hex(
        vector["raw_transaction"]
            .as_str()
            .ok_or("raw transaction")?,
    )?;
    let unblinded = client
        .unblind_own_transaction(&RpcRequestId::new("liquid:unblind:1")?, &raw)
        .await?;
    assert_eq!(unblinded.outputs.len(), 2);
    client
        .require_mempool_acceptance(&RpcRequestId::new("liquid:mempool:1")?, &raw)
        .await?;
    let observation = client
        .observe_output("liquid:observe", &"33".repeat(32), 0)
        .await?;
    assert_eq!(observation.confirmations, 2);
    assert!(observation.unspent);
    assert_eq!(observation.raw_transaction, raw);
    let mempool = client
        .observe_transaction(
            &RpcRequestId::new("liquid:observe:mempool")?,
            &"55".repeat(32),
        )
        .await?;
    assert_eq!(mempool.confirmations, 0);
    assert_eq!(mempool.block_hash, None);
    assert_eq!(
        client
            .observe_transaction(
                &RpcRequestId::new("liquid:observe:malformed")?,
                &"66".repeat(32),
            )
            .await
            .unwrap_err(),
        ElementsdError::Json("transaction confirmation count is not an unsigned integer")
    );
    for (request_id, transaction_id) in [
        ("liquid:observe:missing-blockhash", "77".repeat(32)),
        ("liquid:observe:zero-confirmed", "88".repeat(32)),
    ] {
        assert_eq!(
            client
                .observe_transaction(&RpcRequestId::new(request_id)?, &transaction_id)
                .await
                .unwrap_err(),
            ElementsdError::Json("transaction confirmations and block hash are inconsistent")
        );
    }

    let requests = server.await?;
    assert_eq!(requests.len(), 11);
    assert!(requests[0].starts_with("POST / HTTP/1.1\r\n"));
    assert!(requests[3].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    assert!(requests[4].starts_with("POST / HTTP/1.1\r\n"));
    let transaction_request: Value = serde_json::from_slice(http_body(requests[5].as_bytes()))?;
    assert_eq!(transaction_request["method"], "getrawtransaction");
    let output_request: Value = serde_json::from_slice(http_body(requests[6].as_bytes()))?;
    assert_eq!(output_request["method"], "gettxout");
    let mempool_request: Value = serde_json::from_slice(http_body(requests[7].as_bytes()))?;
    assert_eq!(mempool_request["method"], "getrawtransaction");
    let malformed_request: Value = serde_json::from_slice(http_body(requests[8].as_bytes()))?;
    assert_eq!(malformed_request["method"], "getrawtransaction");
    assert!(!format!("{client:?}").contains("elements-password"));
    Ok(())
}

#[tokio::test]
async fn elementsd_accepts_only_exact_bytes_for_an_already_known_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/liquid-rail-v1.json"
    ))?;
    let network = &fixture["network"];
    let raw_hex = fixture["parser_vectors"][0]["raw_transaction"]
        .as_str()
        .ok_or("raw transaction")?;
    let raw = decode_fixture_hex(raw_hex)?;
    let responses = vec![
        http_response(
            200,
            &json!({
                "result":[{"txid":"33".repeat(32),"allowed":false,"reject-reason":"txn-already-known"}],
                "error":null,
                "id":"liquid:known:policy"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":raw_hex,
                "error":null,
                "id":"liquid:known:raw"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse(network["network_id"].as_str().ok_or("network ID")?)?,
        LiquidAssetId::parse(network["pegged_asset"].as_str().ok_or("pegged asset")?)?,
    )?;
    let admission = client
        .require_mempool_acceptance_or_exact_known(
            &RpcRequestId::new("liquid:known:policy")?,
            &RpcRequestId::new("liquid:known:raw")?,
            &raw,
        )
        .await?;
    assert_eq!(admission, ElementsdMempoolAdmission::ExactKnown);
    let requests = server.await?;
    assert_eq!(requests.len(), 2);
    let known_request: Value = serde_json::from_slice(http_body(requests[1].as_bytes()))?;
    assert_eq!(known_request["method"], "getrawtransaction");
    Ok(())
}

#[tokio::test]
async fn elementsd_spender_lookup_scans_mempool_and_recent_blocks_by_exact_outpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let funding_transaction_id = "22".repeat(32);
    let spending_transaction_id = "33".repeat(32);
    let unrelated_transaction_id = "44".repeat(32);
    let responses = vec![
        http_response(
            200,
            &json!({
                "result":[spending_transaction_id, unrelated_transaction_id],
                "error":null,
                "id":"liquid:spender:mempool"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{
                    "txid":spending_transaction_id,
                    "vin":[{"txid":funding_transaction_id,"vout":7}],
                },
                "error":null,
                "id":"liquid:spender:mempool-0"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{
                    "txid":unrelated_transaction_id,
                    "vin":[{"txid":funding_transaction_id,"vout":8}],
                },
                "error":null,
                "id":"liquid:spender:mempool-1"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        LiquidAssetId::parse(&"11".repeat(32))?,
    )?;

    let spent = client
        .spending_transaction("liquid:spender", &funding_transaction_id, 7)
        .await?;
    assert_eq!(
        spent.spending_transaction_id.as_deref(),
        Some(spending_transaction_id.as_str())
    );
    assert!(
        client
            .spending_transaction("liquid:spender:invalid", &funding_transaction_id, 1 << 30,)
            .await
            .is_err()
    );

    let requests = server.await?;
    let methods = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(http_body(request.as_bytes()))
                .map(|request| request["method"].as_str().map(str::to_owned))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        methods,
        vec![
            Some("getrawmempool".to_owned()),
            Some("getrawtransaction".to_owned()),
            Some("getrawtransaction".to_owned()),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn elementsd_spender_lookup_finds_a_confirmed_spender_without_unsupported_rpc()
-> Result<(), Box<dyn std::error::Error>> {
    let funding_transaction_id = "66".repeat(32);
    let spending_transaction_id = "77".repeat(32);
    let tip_hash = "88".repeat(32);
    let spending_block_hash = "99".repeat(32);
    let responses = vec![
        http_response(
            200,
            &json!({"result":[],"error":null,"id":"liquid:confirmed:mempool"}).to_string(),
        ),
        http_response(
            200,
            &json!({"result":2,"error":null,"id":"liquid:confirmed:block-count"}).to_string(),
        ),
        http_response(
            200,
            &json!({"result":tip_hash,"error":null,"id":"liquid:confirmed:block-hash-2"})
                .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"hash":tip_hash,"tx":[]},
                "error":null,
                "id":"liquid:confirmed:block-2"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":spending_block_hash,
                "error":null,
                "id":"liquid:confirmed:block-hash-1"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{
                    "hash":spending_block_hash,
                    "tx":[{
                        "txid":spending_transaction_id,
                        "vin":[{"txid":funding_transaction_id,"vout":3}],
                    }],
                },
                "error":null,
                "id":"liquid:confirmed:block-1"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        LiquidAssetId::parse(&"11".repeat(32))?,
    )?;

    let spent = client
        .spending_transaction("liquid:confirmed", &funding_transaction_id, 3)
        .await?;
    assert_eq!(
        spent.spending_transaction_id.as_deref(),
        Some(spending_transaction_id.as_str())
    );
    let requests = server.await?;
    let methods = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(http_body(request.as_bytes()))
                .map(|request| request["method"].as_str().map(str::to_owned))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        methods,
        vec![
            Some("getrawmempool".to_owned()),
            Some("getblockcount".to_owned()),
            Some("getblockhash".to_owned()),
            Some("getblock".to_owned()),
            Some("getblockhash".to_owned()),
            Some("getblock".to_owned()),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn elementsd_spender_lookup_distinguishes_unspent_from_spent_outside_the_window()
-> Result<(), Box<dyn std::error::Error>> {
    let funding_transaction_id = "ab".repeat(32);
    let block_hash = "bc".repeat(32);
    for (unspent_result, expected_error) in [
        (json!({"bestblock":block_hash}), None),
        (
            Value::Null,
            Some(ElementsdError::Json(
                "funding output was spent outside the bounded scan window",
            )),
        ),
    ] {
        let responses = vec![
            http_response(
                200,
                &json!({"result":[],"error":null,"id":"liquid:window:mempool"}).to_string(),
            ),
            http_response(
                200,
                &json!({"result":0,"error":null,"id":"liquid:window:block-count"}).to_string(),
            ),
            http_response(
                200,
                &json!({"result":block_hash,"error":null,"id":"liquid:window:block-hash-0"})
                    .to_string(),
            ),
            http_response(
                200,
                &json!({
                    "result":{"hash":block_hash,"tx":[]},
                    "error":null,
                    "id":"liquid:window:block-0"
                })
                .to_string(),
            ),
            http_response(
                200,
                &json!({"result":unspent_result,"error":null,"id":"liquid:window:unspent"})
                    .to_string(),
            ),
        ];
        let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
        let client = ElementsdClient::new(
            endpoint,
            BitcoindAuth::new("elements-user", "elements-password")?,
            BitcoindLimits::default(),
            ElementsdWalletName::new("provider-liquid")?,
            LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
            LiquidAssetId::parse(&"11".repeat(32))?,
        )?;

        let result = client
            .spending_transaction("liquid:window", &funding_transaction_id, 2)
            .await;
        match expected_error {
            None => assert_eq!(result?.spending_transaction_id, None),
            Some(expected_error) => assert_eq!(result.unwrap_err(), expected_error),
        }
        let requests = server.await?;
        let methods = requests
            .iter()
            .map(|request| {
                serde_json::from_slice::<Value>(http_body(request.as_bytes()))
                    .map(|request| request["method"].as_str().map(str::to_owned))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            methods,
            vec![
                Some("getrawmempool".to_owned()),
                Some("getblockcount".to_owned()),
                Some("getblockhash".to_owned()),
                Some("getblock".to_owned()),
                Some("gettxout".to_owned()),
            ]
        );
    }
    Ok(())
}

#[tokio::test]
async fn elementsd_spender_lookup_rejects_multiple_exact_spenders()
-> Result<(), Box<dyn std::error::Error>> {
    let funding_transaction_id = "cd".repeat(32);
    let first_spender = "de".repeat(32);
    let second_spender = "ef".repeat(32);
    let responses = vec![
        http_response(
            200,
            &json!({
                "result":[first_spender,second_spender],
                "error":null,
                "id":"liquid:conflict:mempool"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"txid":first_spender,"vin":[{"txid":funding_transaction_id,"vout":4}]},
                "error":null,
                "id":"liquid:conflict:mempool-0"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":{"txid":second_spender,"vin":[{"txid":funding_transaction_id,"vout":4}]},
                "error":null,
                "id":"liquid:conflict:mempool-1"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        LiquidAssetId::parse(&"11".repeat(32))?,
    )?;

    assert_eq!(
        client
            .spending_transaction("liquid:conflict", &funding_transaction_id, 4)
            .await
            .unwrap_err(),
        ElementsdError::Json("multiple transactions spend the requested outpoint")
    );
    server.await?;
    Ok(())
}

#[tokio::test]
async fn elementsd_spender_lookup_fails_loudly_when_the_mempool_exceeds_its_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let funding_transaction_id = "aa".repeat(32);
    let transactions = (0..=elementsd::MAX_SPENDER_MEMPOOL_TRANSACTIONS)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let response = http_response(
        200,
        &json!({"result":transactions,"error":null,"id":"liquid:bounded:mempool"}).to_string(),
    );
    let (endpoint, server) = spawn_bitcoind(response).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        LiquidAssetId::parse(&"11".repeat(32))?,
    )?;

    assert_eq!(
        client
            .spending_transaction("liquid:bounded", &funding_transaction_id, 0)
            .await
            .unwrap_err(),
        ElementsdError::Json("mempool spender scan exceeds its bound")
    );
    server.await?;
    Ok(())
}

#[tokio::test]
async fn elementsd_lab_mining_helpers_are_wallet_scoped_and_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let responses = vec![
        http_response(
            200,
            &json!({
                "result":"ert1qfixtureaddress",
                "error":null,
                "id":"liquid:mine:address"
            })
            .to_string(),
        ),
        http_response(
            200,
            &json!({
                "result":["22".repeat(32),"33".repeat(32)],
                "error":null,
                "id":"liquid:mine:blocks"
            })
            .to_string(),
        ),
    ];
    let (endpoint, server) = spawn_bitcoind_sequence(responses).await;
    let client = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        LiquidAssetId::parse(&"11".repeat(32))?,
    )?;
    let address = client
        .new_address(&RpcRequestId::new("liquid:mine:address")?)
        .await?;
    let hashes = client
        .generate_to_address(&RpcRequestId::new("liquid:mine:blocks")?, 2, &address)
        .await?;
    assert_eq!(hashes, vec!["22".repeat(32), "33".repeat(32)]);
    assert!(
        client
            .generate_to_address(&RpcRequestId::new("liquid:mine:invalid")?, 0, &address)
            .await
            .is_err()
    );
    let requests = server.await?;
    assert!(requests[0].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    let address_request: Value = serde_json::from_slice(http_body(requests[0].as_bytes()))?;
    assert_eq!(address_request["method"], "getnewaddress");
    let mining_request: Value = serde_json::from_slice(http_body(requests[1].as_bytes()))?;
    assert_eq!(mining_request["method"], "generatetoaddress");
    assert_eq!(mining_request["params"], json!([2, address]));
    Ok(())
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
    let invoice = ClnLightningRail::new(cln_client(&path, ClnLimits::default()))
        .hold_invoice("effect:hold:1", &payment_hash, amount, 604_800, 80)
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

#[tokio::test]
async fn cln_adversarial_hold_policy_probes_and_verifies_the_distinct_rpc() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/provider/cln-adversarial-hold-v1.json"
    ))
    .unwrap();
    let request = &fixture["rpc"]["request"];
    let bolt11 = fixture["response"]["bolt11"].as_str().unwrap();
    let parsed = parse_bolt11(bolt11).unwrap();
    let amount = Millisatoshi::from_millisatoshis(request["amount"].as_u64().unwrap());
    let expiry_seconds = u32::try_from(request["expiry_seconds"].as_u64().unwrap()).unwrap();
    let minimum_final_cltv_delta =
        u32::try_from(request["min_final_cltv_expiry_delta"].as_u64().unwrap()).unwrap();

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
    let mut responses = methods
        .iter()
        .enumerate()
        .map(|(index, method)| {
            json!({
                "jsonrpc":"2.0",
                "id":format!("startup:probe:{index}"),
                "result":{"help":[{"command":format!("{method} usage")}]}
            })
        })
        .collect::<Vec<_>>();
    responses.push(json!({
        "jsonrpc":"2.0",
        "id":"startup:probe:exact",
        "result":{"help":[{"command":format!("{IMMORTAL_REGTEST_HOLD_METHOD} usage")}]}
    }));
    let path = socket_path("cln-adversarial-probe");
    let server = spawn_cln(path.clone(), responses).await;
    let rail =
        ClnLightningRail::with_immortal_regtest_policy(cln_client(&path, ClnLimits::default()));
    rail.probe("startup").await.unwrap();
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), methods.len() + 1);
    assert_eq!(requests.last().unwrap()["method"], "help");
    assert_eq!(
        requests.last().unwrap()["params"]["command"],
        IMMORTAL_REGTEST_HOLD_METHOD
    );
    cleanup_socket(&path);

    let path = socket_path("cln-adversarial-hold");
    let server = spawn_cln(
        path.clone(),
        vec![json!({
            "jsonrpc":"2.0",
            "id":"effect:adversarial-hold:1",
            "result":{"bolt11":bolt11}
        })],
    )
    .await;
    let rail =
        ClnLightningRail::with_immortal_regtest_policy(cln_client(&path, ClnLimits::default()));
    let invoice = rail
        .hold_invoice(
            "effect:adversarial-hold:1",
            request["payment_hash"].as_str().unwrap(),
            amount,
            expiry_seconds,
            minimum_final_cltv_delta,
        )
        .await
        .unwrap();
    assert_eq!(invoice.bolt11, bolt11);
    assert_eq!(parsed.expiry_seconds, u64::from(expiry_seconds));
    assert_eq!(
        parsed.minimum_final_cltv_delta,
        u64::from(minimum_final_cltv_delta)
    );
    let requests = server.await.unwrap();
    assert_eq!(requests[0]["method"], IMMORTAL_REGTEST_HOLD_METHOD);
    assert_eq!(requests[0]["params"], *request);
    cleanup_socket(&path);
}

#[tokio::test]
async fn cln_adversarial_hold_policy_rejects_changed_signed_timeouts() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/provider/cln-adversarial-hold-v1.json"
    ))
    .unwrap();
    let request = &fixture["rpc"]["request"];
    let bolt11 = fixture["response"]["bolt11"].as_str().unwrap();
    let amount = Millisatoshi::from_millisatoshis(request["amount"].as_u64().unwrap());
    for (index, expiry_seconds, minimum_final_cltv_delta) in [(0, 31, 80), (1, 30, 81)] {
        let request_id = format!("effect:adversarial-reject:{index}");
        let path = socket_path(&format!("cln-adv-reject-{index}"));
        let server = spawn_cln(
            path.clone(),
            vec![json!({
                "jsonrpc":"2.0",
                "id":request_id,
                "result":{"bolt11":bolt11}
            })],
        )
        .await;
        let error = cln_client(&path, ClnLimits::default())
            .immortal_regtest_hold_invoice(
                &ClnRequestId::new(request_id).unwrap(),
                request["payment_hash"].as_str().unwrap(),
                amount,
                expiry_seconds,
                minimum_final_cltv_delta,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            ClnError::Json(
                "invoice result does not bind the requested amount, hash, expiry, or final CLTV"
            )
        );
        server.await.unwrap();
        cleanup_socket(&path);
    }
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

async fn spawn_bitcoind_sequence(
    responses: Vec<Vec<u8>>,
) -> (BitcoindEndpoint, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::with_capacity(responses.len());
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests.push(read_http_request(&mut stream).await);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        requests
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

fn decode_fixture_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0 {
        return Err("odd fixture hex length".into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes)
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

fn socket_path(_name: &str) -> PathBuf {
    let sequence = SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // macOS already uses a long per-user TMPDIR, and Unix socket paths have a
    // small fixed limit. The process and sequence keep the compact name unique.
    std::env::temp_dir().join(format!("ip-{}-{sequence}.sock", std::process::id()))
}

fn cleanup_socket(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to remove test socket: {error}"),
    }
}
