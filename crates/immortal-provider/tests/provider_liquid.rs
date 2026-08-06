use immortal_client::liquid::{
    LiquidBeforeFundRequest, LiquidConfidentiality, LiquidExitMode, LiquidFundingVerificationInput,
    LiquidLegPurpose, LiquidSwapType, LiquidUnilateralExitPackage,
};
use immortal_core::{
    liquid::{
        ConfidentialAsset, ConfidentialValue, LiquidAssetId, LiquidNetworkId,
        liquid_tapbranch_hash, liquid_tapleaf_hash, liquid_taproot_output_key,
        parse_liquid_transaction,
    },
    mkt_swp_verify::sha256,
};
use immortal_provider::{
    bitcoind::{BitcoindAuth, BitcoindEndpoint, BitcoindLimits, RpcRequestId},
    elementsd::{
        ELEMENTSD_PRODUCTION_RUNTIME_METHODS, ElementsdClient, ElementsdWalletName,
        ElementsdWalletUtxo,
    },
    liquid::{LiquidEffectOperation, LiquidProviderRail, ProviderLiquidExitRequest},
    store::ProviderStore,
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
};
use secp256k1::{Parity, XOnlyPublicKey};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const NETWORK: &str = "bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ASSET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const LIGHTNING: &str = "swp:1:bip122:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:btc:lightning";
const INTERNAL_KEY: &str = "08228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968";
const OUTPUT_KEY: &str = "6f28a027ecd92a3d9af9798d032bc0040310a15a5dd7c0e0abb8ea8959523009";
const ORIGINAL_OUTPUT_KEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const MERKLE_ROOT: &str = "be8e5d61bd9415b53af92f729857dfeeabd4e26a7827ec20d7ce99703d21548c";
const REFUND_SCRIPT: &str =
    "028c00b17520716022efaca232dd8a7927619a9e5f1eb8f1c8b87436a52a03ae7e1239a1662aac";
const REFUND_CONTROL_BLOCK: &str = "c408228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968ad4f0cd39b48ad95bd00c6f1f1d08ff3a776c62c9c0e7832b71cdf87d5834bcd";
const LIQUID_NUMS_INTERNAL_KEY: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const BITCOIN_REGTEST_NETWORK: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";

#[tokio::test]
async fn provider_liquid_startup_probes_wallet_and_every_runtime_method()
-> Result<(), Box<dyn std::error::Error>> {
    let mut responses = vec![
        rpc_response("liquid-startup:genesis", json!("aa".repeat(32))),
        rpc_response("liquid-startup:sidechain", json!({"pegged_asset":ASSET})),
        rpc_response(
            "liquid-startup:tip",
            json!({"bestblockhash":"bb".repeat(32),"blocks":42}),
        ),
        rpc_response(
            "liquid-startup:wallet",
            json!({"walletname":"provider-liquid"}),
        ),
    ];
    responses.extend(
        ELEMENTSD_PRODUCTION_RUNTIME_METHODS
            .iter()
            .filter(|method| !matches!(**method, "getwalletinfo" | "help"))
            .enumerate()
            .map(|(index, method)| {
                rpc_response(
                    &format!("liquid-startup:capability-{index}"),
                    Value::String(format!("{method} usage")),
                )
            }),
    );
    let (endpoint, server) = spawn_elementsd(responses).await;
    let client = test_elementsd(endpoint)?;
    let view = client.startup_probe("liquid-startup").await?;
    assert_eq!(view.height, 42);
    let requests = server.await?;
    assert_eq!(
        requests.len(),
        ELEMENTSD_PRODUCTION_RUNTIME_METHODS.len() + 2
    );
    assert!(requests[3].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    let methods = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(http_body(request.as_bytes()))
                .map(|request| request["method"].as_str().map(str::to_owned))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        methods
            .iter()
            .filter(|method| method.as_deref() == Some("help"))
            .count(),
        17
    );
    Ok(())
}

#[tokio::test]
async fn provider_liquid_capacity_is_exact_asset_confirmed_and_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    let responses = vec![rpc_response(
        "liquid-capacity",
        json!([
            {
                "txid":"22".repeat(32),
                "vout":1,
                "amount":0.001,
                "asset":ASSET,
                "scriptPubKey":"51",
                "confirmations":6,
                "spendable":true,
                "solvable":true,
                "safe":true
            },
            {
                "txid":"33".repeat(32),
                "vout":2,
                "amount":0.002,
                "asset":ASSET,
                "scriptPubKey":"51",
                "confirmations":7,
                "spendable":false,
                "solvable":true,
                "safe":true
            }
        ]),
    )];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let client = test_elementsd(endpoint)?;
    let capacity = client
        .confirmed_pegged_capacity(&RpcRequestId::new("liquid-capacity")?, 2, 8)
        .await?;
    assert_eq!(capacity.total_sat, 100_000);
    assert_eq!(capacity.utxos.len(), 1);
    assert_eq!(capacity.utxos[0].transaction_id, "22".repeat(32));
    assert_eq!(capacity.utxos[0].confirmations, 6);

    let requests = server.await?;
    let request: Value = serde_json::from_slice(http_body(requests[0].as_bytes()))?;
    assert_eq!(request["method"], "listunspent");
    assert_eq!(request["params"][0], 2);
    assert_eq!(request["params"][3], false);
    assert_eq!(request["params"][4]["maximumCount"], 8);
    assert_eq!(request["params"][4]["asset"], ASSET);
    assert!(requests[0].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test]
async fn provider_liquid_funding_uses_only_reserved_inputs_and_exact_output()
-> Result<(), Box<dyn std::error::Error>> {
    let script_pubkey = decode_hex(&format!("5120{}", "44".repeat(32)));
    let raw_transaction = explicit_funding_transaction(&script_pubkey, 100_000, 500);
    let responses = vec![
        rpc_response(
            "liquid-funding:descriptor",
            json!({"descriptor":format!("raw({})#fixture", encode_hex(&script_pubkey))}),
        ),
        rpc_response("liquid-funding:address", json!(["ert1pfixture"])),
        rpc_response(
            "liquid-funding:fund",
            json!({"psbt":"funded-psbt","fee":0.00000500}),
        ),
        rpc_response(
            "liquid-funding:sign",
            json!({"psbt":"signed-psbt","complete":true}),
        ),
        rpc_response(
            "liquid-funding:finalize",
            json!({"hex":encode_hex(&raw_transaction),"complete":true}),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let client = test_elementsd(endpoint)?;
    let selected = [ElementsdWalletUtxo {
        transaction_id: "66".repeat(32),
        output_index: 0,
        amount_sat: 150_000,
        script_pubkey: "51".to_owned(),
        confirmations: 9,
    }];
    let funding = client
        .create_signed_funding("liquid-funding", &selected, &script_pubkey, 100_000, 2, 500)
        .await?;
    assert_eq!(funding.raw_transaction, raw_transaction);
    assert_eq!(funding.output_index, 0);
    assert_eq!(funding.amount_sat, 100_000);
    assert_eq!(funding.fee_sat, 500);
    assert_eq!(funding.script_pubkey, script_pubkey);

    let requests = server.await?;
    let parsed = requests
        .iter()
        .map(|request| serde_json::from_slice::<Value>(http_body(request.as_bytes())))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        parsed
            .iter()
            .map(|request| request["method"].as_str())
            .collect::<Vec<_>>(),
        vec![
            Some("getdescriptorinfo"),
            Some("deriveaddresses"),
            Some("walletcreatefundedpsbt"),
            Some("walletprocesspsbt"),
            Some("finalizepsbt"),
        ]
    );
    assert_eq!(
        parsed[2]["params"][0],
        json!([{"txid":"66".repeat(32),"vout":0,"sequence":0xffff_fffe_u32}])
    );
    assert_eq!(parsed[2]["params"][3]["add_inputs"], false);
    assert_eq!(parsed[2]["params"][3]["lockUnspents"], true);
    assert_eq!(parsed[2]["params"][3]["replaceable"], false);
    assert_eq!(parsed[2]["params"].as_array().map(Vec::len), Some(6));
    assert_eq!(parsed[2]["params"][4], true);
    assert_eq!(parsed[2]["params"][5], 2);
    assert!(requests[2].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    assert!(requests[3].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test]
async fn provider_liquid_funding_rejects_changed_inputs_and_excess_fee()
-> Result<(), Box<dyn std::error::Error>> {
    let script_pubkey = decode_hex(&format!("5120{}", "44".repeat(32)));
    let raw_transaction = explicit_funding_transaction(&script_pubkey, 100_000, 500);
    let selected = [ElementsdWalletUtxo {
        transaction_id: "55".repeat(32),
        output_index: 3,
        amount_sat: 150_000,
        script_pubkey: "51".to_owned(),
        confirmations: 9,
    }];
    let (endpoint, server) = spawn_elementsd(Vec::new()).await;
    let client = test_elementsd(endpoint)?;
    let multiple = [
        selected[0].clone(),
        ElementsdWalletUtxo {
            transaction_id: "66".repeat(32),
            output_index: 4,
            ..selected[0].clone()
        },
    ];
    let error = client
        .create_signed_funding(
            "liquid-funding-multiple",
            &multiple,
            &script_pubkey,
            100_000,
            2,
            500,
        )
        .await
        .expect_err("multiple funding inputs must fail before rail I/O");
    assert!(error.to_string().contains("bounds are invalid"));
    assert!(server.await?.is_empty());

    let changed_input_responses = vec![
        rpc_response(
            "liquid-funding-input:descriptor",
            json!({"descriptor":format!("raw({})#fixture", encode_hex(&script_pubkey))}),
        ),
        rpc_response("liquid-funding-input:address", json!(["ert1pfixture"])),
        rpc_response(
            "liquid-funding-input:fund",
            json!({"psbt":"funded-psbt","fee":0.00000500}),
        ),
        rpc_response(
            "liquid-funding-input:sign",
            json!({"psbt":"signed-psbt","complete":true}),
        ),
        rpc_response(
            "liquid-funding-input:finalize",
            json!({"hex":encode_hex(&raw_transaction),"complete":true}),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(changed_input_responses).await;
    let client = test_elementsd(endpoint)?;
    let error = client
        .create_signed_funding(
            "liquid-funding-input",
            &selected,
            &script_pubkey,
            100_000,
            2,
            500,
        )
        .await
        .expect_err("changed reserved input must fail");
    assert!(error.to_string().contains("durable reservation"));
    assert_eq!(server.await?.len(), 5);

    let excess_fee_responses = vec![
        rpc_response(
            "liquid-funding-fee:descriptor",
            json!({"descriptor":format!("raw({})#fixture", encode_hex(&script_pubkey))}),
        ),
        rpc_response("liquid-funding-fee:address", json!(["ert1pfixture"])),
        rpc_response(
            "liquid-funding-fee:fund",
            json!({"psbt":"funded-psbt","fee":0.00000501}),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(excess_fee_responses).await;
    let client = test_elementsd(endpoint)?;
    let error = client
        .create_signed_funding(
            "liquid-funding-fee",
            &selected,
            &script_pubkey,
            100_000,
            2,
            500,
        )
        .await
        .expect_err("fee above signed budget must fail");
    assert!(error.to_string().contains("signed fee budget"));
    assert_eq!(server.await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn provider_liquid_rail_rejects_shape_only_exit_before_funding_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request();
    let funding_raw = decode_hex(&request.funding.raw_transaction);
    let funding = parse_liquid_transaction(&funding_raw)?;
    let funding_prefix = &request.funding.transaction_sha256[..16];
    let responses = vec![
        rpc_response(
            &format!("liquid:{funding_prefix}:unblind"),
            json!({"hex":request.funding.trusted_unblind_transaction,"complete":true}),
        ),
        rpc_response(
            &format!("liquid:{funding_prefix}:mempool"),
            json!([{"txid":encode_hex(&funding.transaction_id),"allowed":true}]),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let elementsd = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse(NETWORK)?,
        LiquidAssetId::parse(ASSET)?,
    )?;
    let rail = LiquidProviderRail::new(elementsd);
    let error = rail
        .verify_before_fund(&request)
        .await
        .expect_err("shape-only witness must fail before funding is authorized");
    assert!(error.to_string().contains("signature"));

    let requests = server.await?;
    assert_eq!(requests.len(), 2);
    let parsed = requests
        .iter()
        .map(|request| serde_json::from_slice::<Value>(http_body(request.as_bytes())))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(parsed[0]["method"], "unblindrawtransaction");
    assert_eq!(parsed[1]["method"], "testmempoolaccept");
    assert!(requests[0].starts_with("POST /wallet/provider-liquid HTTP/1.1\r\n"));
    Ok(())
}

#[tokio::test]
async fn provider_liquid_funding_effect_replays_after_store_restart_without_second_rpc()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping Liquid restart test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return Ok(());
    };
    let request = request();
    let funding_raw = decode_hex(&request.funding.raw_transaction);
    let funding = parse_liquid_transaction(&funding_raw)?;
    let funding_prefix = &request.funding.transaction_sha256[..16];
    let responses = vec![
        rpc_response(
            &format!("liquid:{funding_prefix}:unblind"),
            json!({"hex":request.funding.trusted_unblind_transaction,"complete":true}),
        ),
        rpc_response(
            &format!("liquid:{funding_prefix}:mempool"),
            json!([{"txid":encode_hex(&funding.transaction_id),"allowed":true}]),
        ),
        rpc_response(
            &format!("liquid:{funding_prefix}:broadcast-check"),
            json!([{"txid":encode_hex(&funding.transaction_id),"allowed":true}]),
        ),
        rpc_response(
            &format!("liquid:{funding_prefix}:broadcast"),
            Value::String(encode_hex(&funding.transaction_id)),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let rail = LiquidProviderRail::new(test_elementsd(endpoint)?);
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let effect_id = encode_hex(&sha256(format!("liquid-restart:{nonce}").as_bytes()));
    let session_id = encode_hex(&sha256(format!("liquid-session:{nonce}").as_bytes()));
    let order_id = encode_hex(&sha256(format!("liquid-order:{nonce}").as_bytes()));
    let (mut store, _) = ProviderStore::connect(&database_url).await?;
    let first = rail
        .execute_funding_effect_with_operation(
            &mut store,
            &effect_id,
            &session_id,
            &order_id,
            "destination",
            LiquidEffectOperation::ChainFund,
            &request,
            1,
        )
        .await?;
    assert_eq!(
        store
            .public_effect(&effect_id)
            .await?
            .ok_or("stored Liquid funding effect")?
            .request
            .operation,
        "liquid_chain_fund"
    );
    drop(store);
    let mut restarted = ProviderStore::connect_verified(&database_url).await?;
    let replay = rail
        .execute_funding_effect_with_operation(
            &mut restarted,
            &effect_id,
            &session_id,
            &order_id,
            "destination",
            LiquidEffectOperation::ChainFund,
            &request,
            2,
        )
        .await?;
    assert_eq!(replay, first);
    let mut changed = request.clone();
    changed.funding.amount = "100001".to_owned();
    assert!(
        rail.execute_funding_effect_with_operation(
            &mut restarted,
            &effect_id,
            &session_id,
            &order_id,
            "destination",
            LiquidEffectOperation::ChainFund,
            &changed,
            3,
        )
        .await
        .is_err(),
        "changed request bytes must conflict before another RPC"
    );
    let requests = server.await?;
    assert_eq!(requests.len(), 4, "restart replay must not call elementsd");
    Ok(())
}

#[tokio::test]
async fn provider_liquid_exit_effect_replays_after_store_restart_without_second_rpc()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!(
            "skipping Liquid exit restart test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset"
        );
        return Ok(());
    };
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let seed_path = std::env::temp_dir().join(format!(
        "immortal-provider-liquid-exit-restart-seed-{}-{nonce}",
        std::process::id()
    ));
    let mut seed = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_path)?;
    seed.write_all(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")?;
    seed.sync_all()?;
    drop(seed);
    let wallet = ProviderWallet::load(&seed_path, BitcoinNetwork::Regtest)?;
    let signing_path = WalletPath::new(1, false, 11)?;
    let terms = live_swap_terms(&wallet, signing_path, 140)?;
    let funding_raw = explicit_funding_transaction(&terms.script_pubkey, 100_000, 500);
    let destination = wallet.derive_address(WalletPath::new(0, true, 3)?)?;

    let (build_endpoint, build_server) = spawn_elementsd(vec![rpc_response(
        "exit-restart-build:genesis",
        Value::String("aa".repeat(32)),
    )])
    .await;
    let build_rail = LiquidProviderRail::new(test_elementsd(build_endpoint)?);
    let package = build_rail
        .build_signed_exit_package(
            "exit-restart-build",
            &wallet,
            signing_path,
            &funding_raw,
            0,
            100_000,
            &terms.script_pubkey,
            "refund",
            &terms.refund_script,
            &terms.refund_control_block,
            140,
            &destination.script_pubkey,
            500,
            None,
        )
        .await?;
    assert_eq!(build_server.await?.len(), 1);

    let funding_sha256 = encode_hex(&sha256(&funding_raw));
    let exit_raw = decode_hex(&package.transaction);
    let exit = parse_liquid_transaction(&exit_raw)?;
    let exit_prefix = package.transaction_sha256[..16].to_owned();
    let request = LiquidBeforeFundRequest {
        swap_type: LiquidSwapType::Chain,
        purpose: LiquidLegPurpose::RequesterBroadcast,
        input_asset_id: liquid_asset(),
        output_asset_id: format!("swp:1:{BITCOIN_REGTEST_NETWORK}:btc:chain"),
        funding: LiquidFundingVerificationInput {
            raw_transaction: encode_hex(&funding_raw),
            trusted_unblind_transaction: None,
            transaction_sha256: funding_sha256,
            output_index: 0,
            asset_id: liquid_asset(),
            amount: "100000".to_owned(),
            script_pubkey: encode_hex(&terms.script_pubkey),
            taproot_internal_key: LIQUID_NUMS_INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(encode_hex(&terms.merkle_root)),
            confidentiality: LiquidConfidentiality::Explicit,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package: package,
    };
    let provider_request = ProviderLiquidExitRequest::from_before_fund(&request);
    let responses = vec![
        rpc_response(
            &format!("liquid:{exit_prefix}:provider-exit-genesis"),
            Value::String("aa".repeat(32)),
        ),
        rpc_response(
            &format!("liquid:{exit_prefix}:provider-exit-check"),
            json!([{"txid":encode_hex(&exit.transaction_id),"allowed":true}]),
        ),
        rpc_response(
            &format!("liquid:{exit_prefix}:provider-exit-broadcast"),
            Value::String(encode_hex(&exit.transaction_id)),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let rail = LiquidProviderRail::new(test_elementsd(endpoint)?);
    let effect_id = encode_hex(&sha256(format!("liquid-exit-restart:{nonce}").as_bytes()));
    let session_id = encode_hex(&sha256(format!("liquid-exit-session:{nonce}").as_bytes()));
    let order_id = encode_hex(&sha256(format!("liquid-exit-order:{nonce}").as_bytes()));
    let (mut store, _) = ProviderStore::connect(&database_url).await?;
    let first = rail
        .execute_provider_exit_effect(
            &mut store,
            &effect_id,
            &session_id,
            &order_id,
            "source",
            LiquidEffectOperation::ChainRefund,
            &provider_request,
            1,
        )
        .await?;
    assert_eq!(first.transaction_id, encode_hex(&exit.transaction_id));
    assert_eq!(
        store
            .public_effect(&effect_id)
            .await?
            .ok_or("stored provider exit effect")?
            .request
            .operation,
        "liquid_chain_refund"
    );
    drop(store);
    assert_eq!(server.await?.len(), 3);

    let (replay_endpoint, replay_server) = spawn_elementsd(Vec::new()).await;
    let replay_rail = LiquidProviderRail::new(test_elementsd(replay_endpoint)?);
    let mut restarted = ProviderStore::connect_verified(&database_url).await?;
    let replay = replay_rail
        .execute_provider_exit_effect(
            &mut restarted,
            &effect_id,
            &session_id,
            &order_id,
            "source",
            LiquidEffectOperation::ChainRefund,
            &provider_request,
            2,
        )
        .await?;
    assert_eq!(replay, first);

    let mut changed_funding = provider_request.clone();
    changed_funding.funding.amount = "100001".to_owned();
    assert!(
        replay_rail
            .execute_provider_exit_effect(
                &mut restarted,
                &effect_id,
                &session_id,
                &order_id,
                "source",
                LiquidEffectOperation::ChainRefund,
                &changed_funding,
                3,
            )
            .await
            .is_err(),
        "changed funding context must conflict before another RPC"
    );
    let mut changed_exit = provider_request.clone();
    changed_exit
        .exit_package
        .transaction
        .replace_range(0..2, "03");
    assert!(
        replay_rail
            .execute_provider_exit_effect(
                &mut restarted,
                &effect_id,
                &session_id,
                &order_id,
                "source",
                LiquidEffectOperation::ChainRefund,
                &changed_exit,
                4,
            )
            .await
            .is_err(),
        "changed exit bytes must conflict before another RPC"
    );
    assert_eq!(
        replay_server.await?.len(),
        0,
        "restart replay must not call elementsd"
    );
    fs::remove_file(seed_path)?;
    Ok(())
}

#[tokio::test]
async fn provider_liquid_builds_and_independently_verifies_consensus_signed_refund()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let seed_path = std::env::temp_dir().join(format!(
        "immortal-provider-liquid-seed-{}-{nonce}",
        std::process::id()
    ));
    let mut seed = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_path)?;
    seed.write_all(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")?;
    seed.sync_all()?;
    drop(seed);
    let wallet = ProviderWallet::load(&seed_path, BitcoinNetwork::Regtest)?;
    let signing_path = WalletPath::new(1, false, 11)?;
    let signer = wallet.derive_address(signing_path)?;
    let signer = XOnlyPublicKey::from_byte_array(signer.internal_key)?;
    let internal = XOnlyPublicKey::from_byte_array(
        decode_hex(LIQUID_NUMS_INTERNAL_KEY)
            .try_into()
            .map_err(|_| "Liquid NUMS key has another length")?,
    )?;
    let payment_hash = [0x22; 32];
    let mut claim_script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    claim_script.extend_from_slice(&payment_hash);
    claim_script.extend_from_slice(&[0x88, 0x20]);
    claim_script.extend_from_slice(&signer.serialize());
    claim_script.push(0xac);
    let mut refund_script = vec![0x02, 0x8c, 0x00, 0xb1, 0x75, 0x20];
    refund_script.extend_from_slice(&signer.serialize());
    refund_script.push(0xac);
    let claim_hash = liquid_tapleaf_hash(&claim_script)?;
    let refund_hash = liquid_tapleaf_hash(&refund_script)?;
    let root = liquid_tapbranch_hash(claim_hash, refund_hash);
    let (output_key, parity) = liquid_taproot_output_key(internal, Some(root))?;
    let mut funding_script = vec![0x51, 0x20];
    funding_script.extend_from_slice(&output_key.serialize());
    let mut refund_control_block = Vec::with_capacity(65);
    refund_control_block.push(0xc4 | u8::from(parity == Parity::Odd));
    refund_control_block.extend_from_slice(&internal.serialize());
    refund_control_block.extend_from_slice(&claim_hash);
    let funding_raw = explicit_funding_transaction(&funding_script, 100_000, 500);
    let destination = wallet.derive_address(WalletPath::new(0, true, 3)?)?;
    let responses = vec![rpc_response(
        "exit-build:genesis",
        Value::String("aa".repeat(32)),
    )];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let rail = LiquidProviderRail::new(test_elementsd(endpoint)?);
    let package = rail
        .build_signed_exit_package(
            "exit-build",
            &wallet,
            signing_path,
            &funding_raw,
            0,
            100_000,
            &funding_script,
            "refund",
            &refund_script,
            &refund_control_block,
            140,
            &destination.script_pubkey,
            500,
            None,
        )
        .await?;
    let transaction = parse_liquid_transaction(&decode_hex(&package.transaction))?;
    assert_eq!(transaction.lock_time, 140);
    assert_eq!(transaction.inputs[0].script_witness.len(), 3);
    assert_ne!(transaction.inputs[0].script_witness[0], vec![0_u8; 64]);
    assert_eq!(package.path, "refund");
    assert_eq!(package.fee_amount, "500");
    assert_eq!(server.await?.len(), 1);
    fs::remove_file(seed_path)?;
    Ok(())
}

#[tokio::test]
async fn provider_liquid_wallet_claim_stays_unsigned_until_secret_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let seed_path = std::env::temp_dir().join(format!(
        "immortal-provider-liquid-wallet-claim-seed-{}-{nonce}",
        std::process::id()
    ));
    let mut seed = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_path)?;
    seed.write_all(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")?;
    seed.sync_all()?;
    drop(seed);

    let wallet = ProviderWallet::load(&seed_path, BitcoinNetwork::Regtest)?;
    let signing_path = WalletPath::new(1, false, 11)?;
    let terms = live_swap_terms(&wallet, signing_path, 140)?;
    let funding_raw = explicit_funding_transaction(&terms.script_pubkey, 100_000, 500);
    let funding = parse_liquid_transaction(&funding_raw)?;
    let destination = wallet.derive_address(WalletPath::new(0, true, 3)?)?;
    let (endpoint, server) = spawn_elementsd(vec![rpc_response(
        "wallet-claim-build:genesis",
        Value::String("aa".repeat(32)),
    )])
    .await;
    let rail = LiquidProviderRail::new(test_elementsd(endpoint)?);
    let package = rail
        .build_wallet_claim_exit_package(
            "wallet-claim-build",
            &funding_raw,
            0,
            100_000,
            &terms.script_pubkey,
            &terms.claim_script,
            &terms.claim_control_block,
            &destination.script_pubkey,
            500,
            &"44".repeat(32),
            &"45".repeat(32),
        )
        .await?;
    assert_eq!(server.await?.len(), 1);
    assert_eq!(package.mode, LiquidExitMode::Wallet);
    let unsigned = parse_liquid_transaction(&decode_hex(&package.transaction))?;
    assert!(unsigned.inputs[0].script_witness.is_empty());
    let expected_exit_transaction_id = unsigned.transaction_id;
    let request = LiquidBeforeFundRequest {
        swap_type: LiquidSwapType::Reverse,
        purpose: LiquidLegPurpose::CounterpartyLock,
        input_asset_id: LIGHTNING.to_owned(),
        output_asset_id: liquid_asset(),
        funding: LiquidFundingVerificationInput {
            raw_transaction: encode_hex(&funding_raw),
            trusted_unblind_transaction: None,
            transaction_sha256: encode_hex(&sha256(&funding_raw)),
            output_index: 0,
            asset_id: liquid_asset(),
            amount: "100000".to_owned(),
            script_pubkey: encode_hex(&terms.script_pubkey),
            taproot_internal_key: LIQUID_NUMS_INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(encode_hex(&terms.merkle_root)),
            confidentiality: LiquidConfidentiality::Explicit,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package: package,
    };
    let signed =
        rail.complete_wallet_claim_exit(&request, &wallet, signing_path, terms.preimage)?;
    let signed = parse_liquid_transaction(&signed)?;
    assert_eq!(signed.transaction_id, expected_exit_transaction_id);
    assert_ne!(signed.transaction_id, funding.transaction_id);
    assert_eq!(signed.inputs[0].script_witness.len(), 4);
    assert!(
        rail.complete_wallet_claim_exit(&request, &wallet, signing_path, [0x33; 32])
            .is_err()
    );

    fs::remove_file(seed_path)?;
    Ok(())
}

#[tokio::test]
async fn provider_owned_liquid_exit_verifier_binds_claim_refund_and_consensus_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let seed_path = std::env::temp_dir().join(format!(
        "immortal-provider-liquid-owned-exit-seed-{}-{nonce}",
        std::process::id()
    ));
    let mut seed = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_path)?;
    seed.write_all(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")?;
    seed.sync_all()?;
    drop(seed);

    let wallet = ProviderWallet::load(&seed_path, BitcoinNetwork::Regtest)?;
    let signing_path = WalletPath::new(1, false, 11)?;
    let terms = live_swap_terms(&wallet, signing_path, 140)?;
    let funding_raw = explicit_funding_transaction(&terms.script_pubkey, 100_000, 500);
    let destination = wallet.derive_address(WalletPath::new(0, true, 3)?)?;
    let (build_endpoint, build_server) = spawn_elementsd(vec![
        rpc_response("owned-refund-build:genesis", Value::String("aa".repeat(32))),
        rpc_response("owned-claim-build:genesis", Value::String("aa".repeat(32))),
    ])
    .await;
    let build_rail = LiquidProviderRail::new(test_elementsd(build_endpoint)?);
    let refund = build_rail
        .build_signed_exit_package(
            "owned-refund-build",
            &wallet,
            signing_path,
            &funding_raw,
            0,
            100_000,
            &terms.script_pubkey,
            "refund",
            &terms.refund_script,
            &terms.refund_control_block,
            140,
            &destination.script_pubkey,
            500,
            None,
        )
        .await?;
    let claim = build_rail
        .build_signed_exit_package(
            "owned-claim-build",
            &wallet,
            signing_path,
            &funding_raw,
            0,
            100_000,
            &terms.script_pubkey,
            "claim",
            &terms.claim_script,
            &terms.claim_control_block,
            0,
            &destination.script_pubkey,
            500,
            Some(terms.preimage),
        )
        .await?;
    assert_eq!(build_server.await?.len(), 2);

    let refund_request = provider_exit_request(&funding_raw, &terms, refund);
    let claim_request = provider_exit_request(&funding_raw, &terms, claim);
    let mut bad_signature = claim_request.clone();
    mutate_exit_witness_item(&mut bad_signature.exit_package, 0);
    let mut bad_preimage = claim_request.clone();
    mutate_exit_witness_item(&mut bad_preimage.exit_package, 1);
    let mut bad_genesis = refund_request.clone();
    bad_genesis.exit_package.genesis_hash = "bb".repeat(32);
    let responses = vec![
        rpc_response(
            &format!(
                "liquid:{}:provider-exit-genesis",
                &refund_request.exit_package.transaction_sha256[..16]
            ),
            Value::String("aa".repeat(32)),
        ),
        rpc_response(
            &format!(
                "liquid:{}:provider-exit-genesis",
                &claim_request.exit_package.transaction_sha256[..16]
            ),
            Value::String("aa".repeat(32)),
        ),
        rpc_response(
            &format!(
                "liquid:{}:provider-exit-genesis",
                &bad_signature.exit_package.transaction_sha256[..16]
            ),
            Value::String("aa".repeat(32)),
        ),
        rpc_response(
            &format!(
                "liquid:{}:provider-exit-genesis",
                &bad_genesis.exit_package.transaction_sha256[..16]
            ),
            Value::String("aa".repeat(32)),
        ),
    ];
    let (endpoint, server) = spawn_elementsd(responses).await;
    let rail = LiquidProviderRail::new(test_elementsd(endpoint)?);

    let verified_refund = rail.verify_provider_refund(&refund_request).await?;
    assert_eq!(
        verified_refund.transaction_id(),
        encode_hex(
            &parse_liquid_transaction(&decode_hex(&refund_request.exit_package.transaction))?
                .transaction_id
        )
    );
    rail.verify_provider_claim(&claim_request).await?;
    assert!(
        rail.verify_provider_claim(&bad_signature)
            .await
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    assert!(rail.verify_provider_claim(&bad_preimage).await.is_err());
    assert!(rail.verify_provider_claim(&refund_request).await.is_err());
    assert!(rail.verify_provider_refund(&bad_genesis).await.is_err());

    let requests = server.await?;
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|request| {
        serde_json::from_slice::<Value>(http_body(request.as_bytes()))
            .is_ok_and(|request| request["method"] == "getblockhash")
    }));
    assert_eq!(
        LiquidEffectOperation::SubmarineClaim.as_str(),
        "liquid_submarine_claim"
    );
    assert_eq!(
        LiquidEffectOperation::ReverseFund.as_str(),
        "liquid_reverse_fund"
    );
    assert_eq!(
        LiquidEffectOperation::ReverseRefund.as_str(),
        "liquid_reverse_refund"
    );
    fs::remove_file(seed_path)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires scripts/test-provider-liquid.sh disposable elementsd"]
async fn provider_liquid_live_unblinds_own_output() -> Result<(), Box<dyn std::error::Error>> {
    let (elementsd, _, asset) = live_elementsd()?;
    let raw = decode_hex(&live_env("IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_RAW")?);
    let output_index: usize =
        live_env("IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_OUTPUT_INDEX")?.parse()?;
    let amount: u64 = live_env("IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_AMOUNT")?.parse()?;
    let unblinded = elementsd
        .unblind_own_transaction_raw(&RpcRequestId::new("liquid-live-unblind")?, &raw)
        .await?;
    let transaction = parse_liquid_transaction(&unblinded)?;
    let output = transaction
        .outputs
        .get(output_index)
        .ok_or("unblinded live output is absent")?;
    assert_eq!(output.asset, ConfidentialAsset::Explicit(asset));
    assert_eq!(output.value, ConfidentialValue::Explicit(amount));
    assert!(!output.script_pubkey.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires scripts/test-provider-liquid.sh funded elementsd wallet"]
async fn provider_liquid_live_funds_and_broadcasts_signed_refund()
-> Result<(), Box<dyn std::error::Error>> {
    let (elementsd, network, asset) = live_elementsd()?;
    let rail = LiquidProviderRail::new(elementsd.clone());
    let wallet = ProviderWallet::load(
        std::path::Path::new(&live_env("IMMORTAL_LIQUID_LIVE_SEED_FILE")?),
        BitcoinNetwork::Regtest,
    )?;
    let signing_path = WalletPath::new(1, false, 11)?;
    let refund_height = 17;
    let terms = live_swap_terms(&wallet, signing_path, refund_height)?;
    let capacity = elementsd
        .confirmed_pegged_capacity(&RpcRequestId::new("liquid-live-capacity")?, 1, 8)
        .await
        .map_err(|error| format!("live capacity query failed: {error}"))?;
    let selected = capacity
        .utxos
        .iter()
        .max_by_key(|utxo| utxo.amount_sat)
        .cloned()
        .ok_or("live Elements wallet has no confirmed pegged-asset input")?;
    let funding_amount_sat = 1_000_000;
    let funding = elementsd
        .create_signed_funding(
            "liquid-live-funding",
            &[selected],
            &terms.script_pubkey,
            funding_amount_sat,
            2,
            10_000,
        )
        .await
        .map_err(|error| format!("live funding construction failed: {error}"))?;
    let destination = wallet.derive_address(WalletPath::new(0, true, 3)?)?;
    let package = rail
        .build_signed_exit_package(
            "liquid-live-exit",
            &wallet,
            signing_path,
            &funding.raw_transaction,
            funding.output_index,
            funding_amount_sat,
            &terms.script_pubkey,
            "refund",
            &terms.refund_script,
            &terms.refund_control_block,
            refund_height,
            &destination.script_pubkey,
            500,
            None,
        )
        .await
        .map_err(|error| format!("live exit construction failed: {error}"))?;
    let funding_sha256 = encode_hex(&sha256(&funding.raw_transaction));
    let liquid_asset = asset.mkt_asset_id(&network);
    let request = LiquidBeforeFundRequest {
        swap_type: LiquidSwapType::Chain,
        purpose: LiquidLegPurpose::RequesterBroadcast,
        input_asset_id: liquid_asset.clone(),
        output_asset_id: format!("swp:1:{BITCOIN_REGTEST_NETWORK}:btc:chain"),
        funding: LiquidFundingVerificationInput {
            raw_transaction: encode_hex(&funding.raw_transaction),
            trusted_unblind_transaction: None,
            transaction_sha256: funding_sha256.clone(),
            output_index: funding.output_index,
            asset_id: liquid_asset,
            amount: funding_amount_sat.to_string(),
            script_pubkey: encode_hex(&terms.script_pubkey),
            taproot_internal_key: LIQUID_NUMS_INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(encode_hex(&terms.merkle_root)),
            confidentiality: LiquidConfidentiality::Explicit,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package: package,
    };
    let verified = rail
        .verify_before_fund(&request)
        .await
        .map_err(|error| format!("live verify-before-fund failed: {error}"))?;
    let funding_receipt = rail
        .broadcast_funding(&verified)
        .await
        .map_err(|error| format!("live funding broadcast failed: {error}"))?;
    assert_eq!(
        rail.broadcast_funding(&verified).await?,
        funding_receipt,
        "exact parent replay must not create another transaction"
    );
    let expected_exit = parse_liquid_transaction(&decode_hex(&request.exit_package.transaction))?;
    let expected_exit_transaction_id = encode_hex(&expected_exit.transaction_id);
    let record = json!({
        "schema":"openagents.immortal.provider-liquid-live-result.v1",
        "funding_txid":funding_receipt.transaction_id,
        "funding_output_index":funding.output_index,
        "funding_sha256":funding_sha256,
        "funding_raw":request.funding.raw_transaction,
        "refund_txid":expected_exit_transaction_id,
        "refund_sha256":request.exit_package.transaction_sha256,
        "refund_raw":request.exit_package.transaction,
    });
    let result_path = live_env("IMMORTAL_LIQUID_LIVE_RESULT_FILE")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(result_path)?;
    output.write_all(&serde_json::to_vec(&record)?)?;
    output.sync_all()?;
    let exit_receipt = rail
        .broadcast_unilateral_exit(&verified)
        .await
        .map_err(|error| format!("live exit broadcast failed: {error}"))?;
    assert_eq!(exit_receipt.transaction_id, expected_exit_transaction_id);
    assert_eq!(
        rail.broadcast_unilateral_exit(&verified).await?,
        exit_receipt,
        "exact exit replay must not create another transaction"
    );
    Ok(())
}

fn live_elementsd()
-> Result<(ElementsdClient, LiquidNetworkId, LiquidAssetId), Box<dyn std::error::Error>> {
    let network = LiquidNetworkId::parse(&live_env("IMMORTAL_LIQUID_LIVE_NETWORK_ID")?)?;
    let asset = LiquidAssetId::parse(&live_env("IMMORTAL_LIQUID_LIVE_ASSET_ID")?)?;
    let endpoint = BitcoindEndpoint::new(
        "127.0.0.1",
        live_env("IMMORTAL_LIQUID_LIVE_RPC_PORT")?.parse()?,
    )?;
    let elementsd = ElementsdClient::new(
        endpoint,
        BitcoindAuth::new(
            live_env("IMMORTAL_LIQUID_LIVE_RPC_USER")?,
            live_env("IMMORTAL_LIQUID_LIVE_RPC_PASSWORD")?,
        )?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        network.clone(),
        asset,
    )?;
    Ok((elementsd, network, asset))
}

struct LiveSwapTerms {
    script_pubkey: Vec<u8>,
    claim_script: Vec<u8>,
    claim_control_block: Vec<u8>,
    refund_script: Vec<u8>,
    refund_control_block: Vec<u8>,
    merkle_root: [u8; 32],
    preimage: [u8; 32],
}

fn live_swap_terms(
    wallet: &ProviderWallet,
    signing_path: WalletPath,
    refund_height: u32,
) -> Result<LiveSwapTerms, Box<dyn std::error::Error>> {
    let signer =
        XOnlyPublicKey::from_byte_array(wallet.derive_address(signing_path)?.internal_key)?;
    let internal = XOnlyPublicKey::from_byte_array(
        decode_hex(LIQUID_NUMS_INTERNAL_KEY)
            .try_into()
            .map_err(|_| "Liquid NUMS key has another length")?,
    )?;
    let preimage = [0x22; 32];
    let payment_hash = sha256(&preimage);
    let mut claim_script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    claim_script.extend_from_slice(&payment_hash);
    claim_script.extend_from_slice(&[0x88, 0x20]);
    claim_script.extend_from_slice(&signer.serialize());
    claim_script.push(0xac);
    let mut refund_script_number = script_number(refund_height);
    let mut refund_script = Vec::with_capacity(refund_script_number.len() + 37);
    refund_script.push(u8::try_from(refund_script_number.len())?);
    refund_script.append(&mut refund_script_number);
    refund_script.extend_from_slice(&[0xb1, 0x75, 0x20]);
    refund_script.extend_from_slice(&signer.serialize());
    refund_script.push(0xac);
    let claim_hash = liquid_tapleaf_hash(&claim_script)?;
    let refund_hash = liquid_tapleaf_hash(&refund_script)?;
    let merkle_root = liquid_tapbranch_hash(claim_hash, refund_hash);
    let (output_key, parity) = liquid_taproot_output_key(internal, Some(merkle_root))?;
    let mut script_pubkey = vec![0x51, 0x20];
    script_pubkey.extend_from_slice(&output_key.serialize());
    let mut refund_control_block = Vec::with_capacity(65);
    refund_control_block.push(0xc4 | u8::from(parity == Parity::Odd));
    refund_control_block.extend_from_slice(&internal.serialize());
    refund_control_block.extend_from_slice(&claim_hash);
    let mut claim_control_block = Vec::with_capacity(65);
    claim_control_block.push(0xc4 | u8::from(parity == Parity::Odd));
    claim_control_block.extend_from_slice(&internal.serialize());
    claim_control_block.extend_from_slice(&refund_hash);
    Ok(LiveSwapTerms {
        script_pubkey,
        claim_script,
        claim_control_block,
        refund_script,
        refund_control_block,
        merkle_root,
        preimage,
    })
}

fn script_number(value: u32) -> Vec<u8> {
    let mut remaining = value;
    let mut encoded = Vec::with_capacity(5);
    while remaining != 0 {
        encoded.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

fn test_elementsd(
    endpoint: BitcoindEndpoint,
) -> Result<ElementsdClient, Box<dyn std::error::Error>> {
    Ok(ElementsdClient::new(
        endpoint,
        BitcoindAuth::new("elements-user", "elements-password")?,
        BitcoindLimits::default(),
        ElementsdWalletName::new("provider-liquid")?,
        LiquidNetworkId::parse(NETWORK)?,
        LiquidAssetId::parse(ASSET)?,
    )?)
}

fn live_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("missing {name}").into())
}

fn request() -> LiquidBeforeFundRequest {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/liquid-rail-v1.json"
    ))
    .expect("Liquid fixture");
    let vector = &fixture["parser_vectors"][0];
    let replace = |value: &str| {
        value.replace(
            &format!("5120{ORIGINAL_OUTPUT_KEY}"),
            &format!("5120{OUTPUT_KEY}"),
        )
    };
    let funding_hex = replace(vector["raw_transaction"].as_str().expect("raw transaction"));
    let unblind_hex = replace(
        vector["trusted_local_unblind"]
            .as_str()
            .expect("trusted unblind"),
    );
    let funding_raw = decode_hex(&funding_hex);
    let funding = parse_liquid_transaction(&funding_raw).expect("funding transaction");
    let exit_raw = exit_transaction(funding.transaction_id);
    LiquidBeforeFundRequest {
        swap_type: LiquidSwapType::Submarine,
        purpose: LiquidLegPurpose::RequesterBroadcast,
        input_asset_id: liquid_asset(),
        output_asset_id: LIGHTNING.to_owned(),
        funding: LiquidFundingVerificationInput {
            raw_transaction: funding_hex,
            trusted_unblind_transaction: Some(unblind_hex),
            transaction_sha256: encode_hex(&sha256(&funding_raw)),
            output_index: 0,
            asset_id: liquid_asset(),
            amount: "100000".to_owned(),
            script_pubkey: format!("5120{OUTPUT_KEY}"),
            taproot_internal_key: INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(MERKLE_ROOT.to_owned()),
            confidentiality: LiquidConfidentiality::Confidential,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package: LiquidUnilateralExitPackage {
            schema: "openagents.mkt-swp.liquid-exit.v1".to_owned(),
            network_id: NETWORK.to_owned(),
            genesis_hash: "aa".repeat(32),
            asset_id: liquid_asset(),
            funding_transaction_id: encode_hex(&funding.transaction_id),
            funding_output_index: 0,
            funding_amount: "100000".to_owned(),
            funding_script_pubkey: format!("5120{OUTPUT_KEY}"),
            path: "refund".to_owned(),
            script: REFUND_SCRIPT.to_owned(),
            control_block: REFUND_CONTROL_BLOCK.to_owned(),
            timelock: 140,
            spend_input_index: 0,
            fee_output_index: 1,
            fee_amount: "500".to_owned(),
            transaction_sha256: encode_hex(&sha256(&exit_raw)),
            transaction: encode_hex(&exit_raw),
            mode: LiquidExitMode::Presigned,
            wallet_signing_handle_sha256: None,
            preimage_recovery_ref: None,
        },
    }
}

fn provider_exit_request(
    funding_raw: &[u8],
    terms: &LiveSwapTerms,
    exit_package: LiquidUnilateralExitPackage,
) -> ProviderLiquidExitRequest {
    ProviderLiquidExitRequest {
        funding: LiquidFundingVerificationInput {
            raw_transaction: encode_hex(funding_raw),
            trusted_unblind_transaction: None,
            transaction_sha256: encode_hex(&sha256(funding_raw)),
            output_index: 0,
            asset_id: liquid_asset(),
            amount: "100000".to_owned(),
            script_pubkey: encode_hex(&terms.script_pubkey),
            taproot_internal_key: LIQUID_NUMS_INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(encode_hex(&terms.merkle_root)),
            confidentiality: LiquidConfidentiality::Explicit,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package,
    }
}

fn mutate_exit_witness_item(package: &mut LiquidUnilateralExitPackage, witness_index: usize) {
    let mut raw = decode_hex(&package.transaction);
    let parsed = parse_liquid_transaction(&raw).expect("signed exit transaction");
    let witness = parsed.inputs[0]
        .script_witness
        .get(witness_index)
        .expect("target witness item");
    let offset = raw
        .windows(witness.len())
        .position(|window| window == witness)
        .expect("witness bytes in transaction");
    raw[offset] ^= 1;
    package.transaction = encode_hex(&raw);
    package.transaction_sha256 = encode_hex(&sha256(&raw));
}

fn exit_transaction(funding_transaction_id: [u8; 32]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&2_i32.to_le_bytes());
    raw.push(1);
    raw.push(1);
    let mut wire_transaction_id = funding_transaction_id;
    wire_transaction_id.reverse();
    raw.extend_from_slice(&wire_transaction_id);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0);
    raw.extend_from_slice(&0xffff_fffe_u32.to_le_bytes());
    raw.push(2);
    push_explicit_output(&mut raw, 99_500, &decode_hex(&format!("5120{OUTPUT_KEY}")));
    push_explicit_output(&mut raw, 500, &[]);
    raw.extend_from_slice(&140_u32.to_le_bytes());
    raw.push(0);
    raw.push(0);
    raw.push(3);
    push_bytes(&mut raw, &[1_u8; 64]);
    push_bytes(&mut raw, &decode_hex(REFUND_SCRIPT));
    push_bytes(&mut raw, &decode_hex(REFUND_CONTROL_BLOCK));
    raw.push(0);
    for _ in 0..2 {
        raw.push(0);
        raw.push(0);
    }
    raw
}

fn explicit_funding_transaction(script_pubkey: &[u8], amount_sat: u64, fee_sat: u64) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&2_i32.to_le_bytes());
    raw.push(0);
    raw.push(1);
    raw.extend_from_slice(&[0x66; 32]);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0);
    raw.extend_from_slice(&0xffff_fffe_u32.to_le_bytes());
    raw.push(2);
    push_explicit_output(&mut raw, amount_sat, script_pubkey);
    push_explicit_output(&mut raw, fee_sat, &[]);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw
}

fn push_explicit_output(raw: &mut Vec<u8>, amount: u64, script_pubkey: &[u8]) {
    raw.push(1);
    raw.extend_from_slice(&[0x11; 32]);
    raw.push(1);
    raw.extend_from_slice(&amount.to_be_bytes());
    raw.push(0);
    push_bytes(raw, script_pubkey);
}

fn push_bytes(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.push(u8::try_from(bytes.len()).expect("fixture compact size"));
    raw.extend_from_slice(bytes);
}

fn liquid_asset() -> String {
    format!("swp:1:{NETWORK}:elements:{ASSET}:liquid")
}

async fn spawn_elementsd(responses: Vec<Vec<u8>>) -> (BitcoindEndpoint, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::with_capacity(responses.len());
        for response in responses {
            let (mut stream, _) = listener.accept().await.expect("fixture connection");
            requests.push(read_http_request(&mut stream).await);
            stream.write_all(&response).await.expect("fixture response");
            stream.shutdown().await.expect("fixture shutdown");
        }
        requests
    });
    (
        BitcoindEndpoint::new("127.0.0.1", address.port()).expect("fixture endpoint"),
        server,
    )
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let body_start = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.expect("fixture request");
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&request[..body_start]).expect("HTTP head");
    let content_length = head
        .split("\r\n")
        .find_map(|line| {
            line.strip_prefix("Content-Length: ")
                .and_then(|length| length.parse::<usize>().ok())
        })
        .expect("content length");
    while request.len() - body_start < content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.expect("fixture body");
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(request).expect("HTTP request")
}

fn http_body(request: &[u8]) -> &[u8] {
    let start = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP body")
        + 4;
    &request[start..]
}

fn rpc_response(id: &str, result: Value) -> Vec<u8> {
    let body = json!({"result":result,"error":null,"id":id}).to_string();
    format!(
        "HTTP/1.1 200 Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture hex is lowercase"),
    }
}
