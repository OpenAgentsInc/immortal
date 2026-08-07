#![cfg(feature = "funded")]

use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::provider_support::effect_id;
use immortal_provider::store::{
    ArkReserveUnit, HardReservationRequest, OutPoint, ProviderStore, ProviderStoreError,
    ReservationOutcome, StoreWriteOutcome,
};
use immortal_provider::{
    ark_funded::{
        ARK_TRANSFER_COMMAND_SCHEMA, ArkFundedRail, ArkTransferCommand, ArkTransferMaterial,
    },
    arkd::{ArkdClient, ArkdEndpoint, ArkdExpectedOperator, ArkdLimits},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const FIXTURE: &str = include_str!("../../../tests/fixtures/provider/ark-runtime-v1.json");
const ARKD_REST_FIXTURE: &str = include_str!("../../../tests/fixtures/provider/arkd-rest-v1.json");

#[test]
fn ark_reserve_fixture_is_closed_and_custody_free() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("Ark provider fixture must parse");
    assert_eq!(
        fixture["schema"],
        "openagents.immortal.provider-ark-runtime.v1"
    );
    let cases = fixture["reservation_cases"]
        .as_array()
        .expect("Ark reservation cases must be an array");
    let actual = cases
        .iter()
        .map(|case| {
            (
                case["name"]
                    .as_str()
                    .expect("Ark reservation case name must be a string"),
                case["expected"]
                    .as_str()
                    .expect("Ark reservation expectation must be a string"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual,
        BTreeMap::from([
            ("ark-reserve-v1-changed-proof", "conflict"),
            ("ark-reserve-v1-exact-replay", "replay"),
            ("ark-reserve-v1-first-writer", "reserved"),
            (
                "ark-reserve-v1-operator-alias-double-use",
                "reserve_unit_unavailable",
            ),
            (
                "ark-reserve-v1-other-bucket-double-use",
                "reserve_unit_unavailable",
            ),
            ("ark-reserve-v1-release-then-reuse", "reserved"),
            (
                "ark-reserve-v1-unresolved-blocks-reuse",
                "reserve_unit_unavailable",
            ),
        ])
    );
    assert_eq!(
        fixture["transfer_effect"]["command_schema"],
        ARK_TRANSFER_COMMAND_SCHEMA
    );
    assert_eq!(
        fixture["transfer_effect"]["persist_before_operator_rpc"],
        true
    );
    assert_eq!(fixture["transfer_effect"]["mkt_pair_advertisement"], false);
    assert_eq!(fixture["transfer_effect"]["native_session_actor"], false);
    let transfer_cases = fixture["transfer_effect"]["cases"]
        .as_array()
        .expect("Ark transfer cases must be an array");
    assert_eq!(transfer_cases.len(), 6);
    let normalized = FIXTURE.replace('_', "").to_ascii_lowercase();
    for forbidden in [
        "seedvalue",
        "preimagevalue",
        "macaroonvalue",
        "claimkeyvalue",
        "refundkeyvalue",
        "feekeyvalue",
        "spendkeyvalue",
        "vtxokeyvalue",
        "privatenoncevalue",
        "operatortokenvalue",
    ] {
        assert!(!normalized.contains(forbidden));
    }
}

#[tokio::test]
async fn ark_reserve_units_are_globally_atomic_and_restart_safe() {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let id = |label: &str| digest(format!("provider-ark-store:{namespace}:{label}").as_bytes());
    let bucket = |label: &str| format!("ark-{}", &id(label)[..32]);
    let asset_id = "swp:1:bip122:00000000000000000000000000000000:btc:ark:arkade";
    let reserve = ArkReserveUnit {
        protocol_family: "arkade".to_owned(),
        operator_identity_sha256: id("operator"),
        vtxo: OutPoint {
            txid: id("vtxo"),
            vout: 7,
        },
        proof_sha256: id("proof"),
    };

    let (mut first, migration) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    assert!(migration.applied_versions.len() <= 4);
    let mut second = ProviderStore::connect_verified(&database_url)
        .await
        .expect("provider migrations must verify");

    let bucket_names = [
        bucket("first"),
        bucket("other"),
        bucket("alias"),
        bucket("unresolved"),
        bucket("blocked"),
    ];
    for bucket_name in &bucket_names {
        first
            .configure_capacity_bucket(bucket_name, asset_id, 100, 1)
            .await
            .expect("Ark capacity bucket must configure");
    }

    let first_request = reservation(&id, "first", &bucket_names[0], asset_id, &reserve);
    assert!(matches!(
        first
            .reserve(&first_request)
            .await
            .expect("first Ark reservation must resolve"),
        ReservationOutcome::Reserved(_)
    ));
    assert!(matches!(
        second
            .reserve(&first_request)
            .await
            .expect("exact Ark replay must resolve"),
        ReservationOutcome::Replay(_)
    ));

    let mut changed_proof = first_request.clone();
    changed_proof
        .ark_reserve
        .as_mut()
        .expect("Ark reserve must be present")
        .proof_sha256 = id("changed-proof");
    assert!(matches!(
        first.reserve(&changed_proof).await,
        Err(ProviderStoreError::Conflict(_))
    ));

    let other_bucket = reservation(&id, "other", &bucket_names[1], asset_id, &reserve);
    let alias = reservation(&id, "alias", &bucket_names[2], asset_id, &reserve);
    let (other_outcome, alias_outcome) =
        tokio::join!(first.reserve(&other_bucket), second.reserve(&alias),);
    for outcome in [other_outcome, alias_outcome] {
        assert_eq!(
            outcome.expect("competing Ark reservation must resolve"),
            ReservationOutcome::ArkReserveUnitUnavailable(reserve.canonical_id())
        );
    }

    assert_eq!(
        first
            .release_reservation(&first_request.reservation_id, "cancelled", 10)
            .await
            .expect("Ark reservation release must persist"),
        StoreWriteOutcome::Stored
    );
    assert!(matches!(
        second
            .reserve(&other_bucket)
            .await
            .expect("released Ark reserve unit must be reusable"),
        ReservationOutcome::Reserved(_)
    ));
    second
        .release_reservation(&other_bucket.reservation_id, "cancelled", 11)
        .await
        .expect("reused Ark reservation release must persist");

    let unresolved = reservation(&id, "unresolved", &bucket_names[3], asset_id, &reserve);
    assert!(matches!(
        first
            .reserve(&unresolved)
            .await
            .expect("Ark unresolved setup reservation must resolve"),
        ReservationOutcome::Reserved(_)
    ));
    first
        .mark_reservation_unresolved(
            &unresolved.reservation_id,
            "ark_exit_unknown",
            &json!({"reserve_unit":reserve.canonical_id()}),
            12,
        )
        .await
        .expect("Ark unresolved state must persist");
    let blocked = reservation(&id, "blocked", &bucket_names[4], asset_id, &reserve);
    assert_eq!(
        second
            .reserve(&blocked)
            .await
            .expect("Ark unresolved blocker must resolve"),
        ReservationOutcome::ArkReserveUnitUnavailable(reserve.canonical_id())
    );
}

#[tokio::test]
async fn ark_transfer_effect_is_exact_replay_and_retains_only_public_digests() {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let fixture: Value =
        serde_json::from_str(ARKD_REST_FIXTURE).expect("Arkd REST fixture must parse");
    let submit = &fixture["calls"][2];
    let signed_transaction = submit["request"]["body"]["signedArkTx"]
        .as_str()
        .expect("fixture signed Ark transaction")
        .to_owned();
    let output_vtxo_id = format!(
        "{}:0",
        submit["response"]["arkTxid"]
            .as_str()
            .expect("fixture Ark transaction ID")
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture Arkd listener");
    let port = listener.local_addr().expect("fixture Arkd address").port();
    let server_fixture = fixture.clone();
    let server = tokio::spawn(async move {
        let mut vtxo_response = server_fixture["calls"][1]["response"].clone();
        vtxo_response["vtxos"][0]["script"] = Value::String(
            "5120a59934408e9c1e7d1e06932683d749ea4c613143b6b5dc5c922082c31adf9126".to_owned(),
        );
        let responses = [
            (200_u16, server_fixture["calls"][0]["response"].clone()),
            (404_u16, json!({})),
            (200, server_fixture["calls"][2]["response"].clone()),
            (503, json!({"error":"fixture restart boundary"})),
            (200, server_fixture["calls"][0]["response"].clone()),
            (200, vtxo_response),
        ];
        let expected_paths = [
            "/v1/info",
            "/v1/indexer/vtxos?",
            "/v1/tx/submit",
            "/v1/tx/finalize",
            "/v1/info",
            "/v1/indexer/vtxos?",
        ];
        for ((status, response), expected_path) in responses.into_iter().zip(expected_paths) {
            let (mut stream, _) = listener.accept().await.expect("fixture Arkd accept");
            let request = read_http_request(&mut stream).await;
            assert!(request.contains(expected_path));
            write_http_response(&mut stream, status, &response).await;
        }
    });

    let operator_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/provider/arkd-operator-regtest-v1.json")
        .canonicalize()
        .expect("operator fixture path");
    let expected = ArkdExpectedOperator::load_document(&operator_path).expect("operator fixture");
    let client = ArkdClient::new(
        ArkdEndpoint::plaintext_regtest("127.0.0.1", port).expect("fixture Arkd endpoint"),
        expected,
        ArkdLimits::default(),
    )
    .expect("fixture Arkd client");
    let rail = ArkFundedRail::new(client);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let id = |label: &str| digest(format!("provider-ark-effect:{namespace}:{label}").as_bytes());
    let (mut store, _) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    let exit_package_sha256 = id("exit-package");
    let order_id = id("order");
    let leg_id = "destination";
    let transfer_effect_id =
        effect_id(&order_id, "ark_transfer", leg_id).expect("Ark transfer effect ID");
    let operator_identity_sha256 = fixture["operator"]["operator_identity_sha256"]
        .as_str()
        .expect("fixture operator identity")
        .to_owned();
    let signed_transaction_sha256 =
        digest(&decode_hex(&signed_transaction).expect("fixture transaction hex"));
    let material = ArkTransferMaterial {
        asset_id: rail.asset_id(),
        input_vtxo_ids: vec![format!("{}:0", "aa".repeat(32))],
        output_vtxo_id: output_vtxo_id.clone(),
        amount_sat: 100_000,
        output_script_pubkey:
            "5120a59934408e9c1e7d1e06932683d749ea4c613143b6b5dc5c922082c31adf9126".to_owned(),
        signed_vtxo_graph_sha256: id("signed-graph"),
        exit_package_sha256: exit_package_sha256.clone(),
        final_ark_transaction_sha256: signed_transaction_sha256.clone(),
        signed_ark_transaction: signed_transaction.clone(),
        checkpoint_transactions: Vec::new(),
        final_checkpoint_transactions: Vec::new(),
    };
    let session_id = id("session");
    let command = ArkTransferCommand {
        schema: ARK_TRANSFER_COMMAND_SCHEMA.to_owned(),
        session_id: session_id.clone(),
        leg_id: leg_id.to_owned(),
        client_snapshot: json!({
            "schema":"openagents.immortal.ark-client-snapshot.v1",
            "persisted":{
                "artifact_sha256":exit_package_sha256,
                "artifact_ref":"ark-exit:provider-test",
                "order_id":order_id,
                "effect_id":transfer_effect_id,
                "vtxo_id":output_vtxo_id,
                "operator_identity_sha256":operator_identity_sha256,
                "esplora_urls":["http://127.0.0.1:3002"],
                "transactions":[{
                    "transaction_id":submit["response"]["arkTxid"],
                    "signed_transaction_sha256":signed_transaction_sha256,
                    "parent_transaction_id":null,
                    "earliest_broadcast_height":1,
                    "latest_safe_broadcast_height":1000
                }]
            }
        }),
        material,
    };
    assert!(
        rail.execute_command(&mut store, &command, 10)
            .await
            .is_err()
    );
    let receipt = rail
        .execute_command(&mut store, &command, 11)
        .await
        .expect("pending Ark transfer recovered from its exact output VTXO");
    assert_eq!(receipt.output_vtxo_id, output_vtxo_id);
    server.await.expect("fixture Arkd server");

    let replay = rail
        .execute_command(&mut store, &command, 12)
        .await
        .expect("applied Ark transfer replay");
    assert_eq!(replay, receipt);
    let stored = store
        .public_effect(&transfer_effect_id)
        .await
        .expect("Ark effect lookup")
        .expect("Ark effect must exist");
    let retained = serde_json::to_string(&stored.request.public_request)
        .expect("retained Ark request must serialize");
    assert!(!retained.contains(&signed_transaction));
    assert!(retained.contains(&command.material.signed_vtxo_graph_sha256));
    assert_eq!(
        stored.external_reference.as_deref(),
        Some(output_vtxo_id.as_str())
    );

    let mut changed = command;
    changed.material.signed_vtxo_graph_sha256 = id("changed-graph");
    assert!(
        rail.execute_command(&mut store, &changed, 13)
            .await
            .is_err()
    );
    changed.material.signed_vtxo_graph_sha256 = id("signed-graph");
    changed.material.exit_package_sha256 = id("changed-exit-package");
    assert!(
        rail.execute_command(&mut store, &changed, 14)
            .await
            .is_err()
    );
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream.read(&mut buffer).await.expect("fixture Arkd read");
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let header = std::str::from_utf8(&bytes[..header_end]).expect("fixture Arkd header");
        let content_length = header
            .split("\r\n")
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or_default();
        if bytes.len() >= header_end + content_length {
            return String::from_utf8(bytes).expect("fixture Arkd request");
        }
    }
}

async fn write_http_response(stream: &mut TcpStream, status: u16, value: &Value) {
    let body = serde_json::to_vec(value).expect("fixture Arkd response JSON");
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Service Unavailable",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .expect("fixture Arkd response header");
    stream
        .write_all(&body)
        .await
        .expect("fixture Arkd response body");
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex length is odd".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn reservation(
    id: &impl Fn(&str) -> String,
    label: &str,
    bucket_id: &str,
    asset_id: &str,
    reserve: &ArkReserveUnit,
) -> HardReservationRequest {
    HardReservationRequest {
        reservation_id: id(&format!("{label}-reservation")),
        effect_id: id(&format!("{label}-effect")),
        session_id: id(&format!("{label}-session")),
        bucket_id: bucket_id.to_owned(),
        asset_id: asset_id.to_owned(),
        amount: 50,
        request_sha256: id(&format!("{label}-request")),
        expected_allocation_sequence: 1,
        expires_at: 1_000,
        utxos: Vec::new(),
        ark_reserve: Some(reserve.clone()),
        created_at: 3,
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
