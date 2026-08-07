#![cfg(feature = "funded")]

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use immortal_provider::store::{
    ArkReserveUnit, HardReservationRequest, OutPoint, ProviderStore, ProviderStoreError,
    ReservationOutcome, StoreWriteOutcome,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../../../tests/fixtures/provider/ark-runtime-v1.json");

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
