//! Optional server-side MKT-SWP coordination claims and bounded verification hooks.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    domain::{
        Event, MKT_QUOTE_CLASSES, MKT_QUOTE_KIND, MKT_RESERVATION_CLASSES, MKT_STATUS_KIND,
        MKT_STATUS_STATES, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MktProfileSupport,
        RelaySigner, validate_mkt_swp_evidence_reference,
    },
    market::{MarketSigner, unwrap_mkt_record_for_handler},
    mkt_swp_verify::Transaction,
};

pub const MKT_SWP_COORDINATION_EXTENSION: &str = "mkt-swp-coordination:1";
pub const MKT_SWP_COORDINATION_CONFORMANCE_ENV: &str =
    "IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256";
pub const MKT_SWP_COORDINATION_SWEEP_ENV: &str = "IMMORTAL_MKT_SWP_COORDINATION_SWEEP_SECONDS";
pub const MKT_SWP_COORDINATION_DEFAULT_SWEEP_SECONDS: u64 = 30;
pub const MKT_SWP_MAX_ACTIVE_RESERVATIONS_PER_BUCKET: usize = 1_024;
pub const MKT_SWP_MAX_STATUS_SEQUENCE: u64 = 4_095;
pub const MKT_SWP_MAX_FORKS_PER_SEQUENCE: usize = 8;
pub const MKT_SWP_MAX_PUBLIC_EVIDENCE_PER_RECORD: usize = 8;
pub const MKT_SWP_MAX_PUBLIC_TRANSACTION_BYTES: usize = 16_384;
pub const MKT_SWP_STATUS_QUERY_ROW_LIMIT: usize = 32_769;

const CONFIGURATION_SCHEMA_V1: &str = concat!(
    "openagents.mkt-swp.coordination.config.v1\n",
    "activation=exact_fixture_migration_config_sha256\n",
    "requires=relay_url,relay_signer\n",
    "private_extension=handler_committed_capacity\n",
    "sweep_seconds=1..3600\n",
    "public_hook=bitcoin_transaction_v1\n",
    "public_observation=kind1985,measured,observation_not_authority\n",
    "private_storage=identifiers_and_hashes_only\n",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpCoordinationInput {
    pub wrap_event_id: String,
    pub source_event_id: String,
    pub claim: MktSwpCoordinationClaim,
    pub public_evidence: Vec<MktSwpPublicEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MktSwpCoordinationClaim {
    Reservation(MktSwpReservationClaim),
    Status(MktSwpStatusClaim),
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpReservationClaim {
    pub quote_event_id: String,
    pub provider_pubkey: String,
    pub session_id: String,
    pub rfq_event_id: String,
    pub reservation_id: String,
    pub capacity_bucket_id: Option<String>,
    pub reserved_asset_id: Option<String>,
    pub reservation_class: String,
    pub reserved_amount: i64,
    pub handler_committed_capacity: i64,
    pub allocation_sequence: Option<i64>,
    pub proof_class: Option<String>,
    pub proof_strength: i16,
    pub proof_ref_sha256: Option<String>,
    pub reserve_unit_sha256: Option<String>,
    pub capacity_commitment_sha256: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpStatusClaim {
    pub status_event_id: String,
    pub author_pubkey: String,
    pub author_role: String,
    pub counterparty_pubkey: String,
    pub session_id: String,
    pub order_event_id: String,
    pub sequence: i64,
    pub previous_event_id: Option<String>,
    pub state: String,
    pub swp_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpPublicEvidence {
    pub evidence_class: String,
    pub rail_reference: String,
    pub artifact_sha256: String,
    pub view: String,
    pub view_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpCoordinationOutcome {
    pub accepted: bool,
    pub code: String,
    pub observation_event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpStatusSequence {
    pub sequence: u64,
    pub event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktSwpStatusView {
    pub sequences: Vec<MktSwpStatusSequence>,
    pub gaps: Vec<u64>,
    pub forks: BTreeMap<u64, Vec<String>>,
}

pub fn coordination_conformance_sha256() -> String {
    let mut digest = Sha256::new();
    digest.update(b"openagents.mkt-swp.coordination.conformance.v1\0");
    digest.update(include_bytes!(
        "../../../tests/fixtures/nipmkt/swp-coordination-v1.json"
    ));
    digest.update(b"\0");
    digest.update(include_bytes!(
        "../../../migrations/0011_mkt_swp_coordination.sql"
    ));
    digest.update(b"\0");
    digest.update(CONFIGURATION_SCHEMA_V1.as_bytes());
    lower_hex(&digest.finalize())
}

pub fn parse_coordination_wrap(
    wrap: &Event,
    relay_signer: &RelaySigner,
) -> Result<Option<MktSwpCoordinationInput>, String> {
    if wrap.gift_wrap_recipient() != Some(relay_signer.pubkey()) {
        return Err("MKT-SWP coordination wrap is not addressed to the configured handler".into());
    }
    let recipient = MarketSigner::from_relay_signer(relay_signer.clone());
    let profiles = [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }];
    let Some(delivered) = unwrap_mkt_record_for_handler(wrap, &recipient, &profiles)? else {
        return Ok(None);
    };
    let event = delivered.record().event().clone();
    let envelope = delivered.record().envelope().clone();
    let profile = envelope
        .body
        .get("mkt_swp")
        .and_then(Value::as_object)
        .ok_or_else(|| "MKT-SWP coordination record requires an mkt_swp object".to_owned())?;
    let public_evidence = parse_public_evidence(profile, &event)?;
    let claim = match event.kind {
        MKT_QUOTE_KIND => MktSwpCoordinationClaim::Reservation(parse_reservation(
            &event,
            &envelope.session_id,
            profile,
        )?),
        MKT_STATUS_KIND => {
            MktSwpCoordinationClaim::Status(parse_status(&event, &envelope.session_id, profile)?)
        }
        _ => MktSwpCoordinationClaim::Observed,
    };
    Ok(Some(MktSwpCoordinationInput {
        wrap_event_id: wrap.id.clone(),
        source_event_id: event.id,
        claim,
        public_evidence,
    }))
}

pub fn status_view_from_rows(rows: Vec<(u64, String)>) -> Result<MktSwpStatusView, String> {
    if rows.len() > MKT_SWP_STATUS_QUERY_ROW_LIMIT {
        return Err("MKT-SWP status query exceeds the bounded row limit".to_owned());
    }
    let mut grouped = BTreeMap::<u64, Vec<String>>::new();
    for (sequence, event_id) in rows {
        if sequence > MKT_SWP_MAX_STATUS_SEQUENCE {
            return Err("MKT-SWP status sequence exceeds the configured maximum".to_owned());
        }
        let event_ids = grouped.entry(sequence).or_default();
        if event_ids.len() >= MKT_SWP_MAX_FORKS_PER_SEQUENCE {
            return Err("MKT-SWP status sequence exceeds the fork bound".to_owned());
        }
        event_ids.push(event_id);
    }
    for event_ids in grouped.values_mut() {
        event_ids.sort();
        event_ids.dedup();
    }
    let maximum = grouped.keys().next_back().copied();
    let gaps = maximum
        .map(|maximum| {
            (0..=maximum)
                .filter(|sequence| !grouped.contains_key(sequence))
                .collect()
        })
        .unwrap_or_default();
    let forks = grouped
        .iter()
        .filter(|(_, event_ids)| event_ids.len() > 1)
        .map(|(sequence, event_ids)| (*sequence, event_ids.clone()))
        .collect();
    let sequences = grouped
        .into_iter()
        .map(|(sequence, event_ids)| MktSwpStatusSequence {
            sequence,
            event_ids,
        })
        .collect();
    Ok(MktSwpStatusView {
        sequences,
        gaps,
        forks,
    })
}

fn parse_reservation(
    event: &Event,
    session_id: &str,
    profile: &Map<String, Value>,
) -> Result<MktSwpReservationClaim, String> {
    let quote_class = single_tag(event, "quote")?;
    require_enum(quote_class, MKT_QUOTE_CLASSES, "Quote class")?;
    let reservation_class = single_tag(event, "reservation")?;
    require_enum(
        reservation_class,
        MKT_RESERVATION_CLASSES,
        "reservation class",
    )?;
    let requester = single_counterparty(event, "requester")?;
    if requester == event.pubkey {
        return Err("MKT-SWP Quote provider and requester must be distinct".to_owned());
    }
    let rfq_event_id = single_marked_event(event, "rfq")?.to_owned();
    let expiration = single_tag(event, "expiration")?
        .parse::<u64>()
        .map_err(|_| "MKT-SWP Quote expiration must be an unsigned integer".to_owned())?;
    let expiration = pg_i64(expiration, "MKT-SWP Quote expiration")?;

    if reservation_class == "none" {
        if quote_class != "indicative" {
            return Err("a firm MKT-SWP Quote must use a soft or hard reservation".to_owned());
        }
        if profile
            .get("reservation_terms")
            .is_some_and(|terms| !terms.is_null())
        {
            return Err("reservation=none must not carry reservation terms".to_owned());
        }
        return Ok(MktSwpReservationClaim {
            quote_event_id: event.id.clone(),
            provider_pubkey: event.pubkey.clone(),
            session_id: session_id.to_owned(),
            rfq_event_id,
            reservation_id: event.id.clone(),
            capacity_bucket_id: None,
            reserved_asset_id: None,
            reservation_class: reservation_class.to_owned(),
            reserved_amount: 0,
            handler_committed_capacity: 0,
            allocation_sequence: None,
            proof_class: None,
            proof_strength: 0,
            proof_ref_sha256: None,
            reserve_unit_sha256: None,
            capacity_commitment_sha256: None,
            expires_at: None,
        });
    }
    if quote_class != "firm" {
        return Err("a reserving MKT-SWP Quote must be firm".to_owned());
    }
    let terms = profile
        .get("reservation_terms")
        .and_then(Value::as_object)
        .ok_or_else(|| "a reserving MKT-SWP Quote requires reservation_terms".to_owned())?;
    let reservation_id = lower_hex_member(terms, "reservation_id")?;
    let capacity_bucket_id = identifier_member(terms, "capacity_bucket_id")?;
    let reserved_asset_id = asset_id_member(terms, "reserved_asset_id")?;
    let reserved_amount = positive_decimal_member(terms, "reserved_amount")?;
    let handler_committed_capacity = positive_decimal_member(terms, "handler_committed_capacity")?;
    if reserved_amount > handler_committed_capacity {
        return Err("reserved_amount exceeds handler_committed_capacity".to_owned());
    }
    let allocation_sequence = decimal_member(terms, "allocation_sequence")?;
    let proof_class = string_member(terms, "proof_class")?;
    let proof_strength = proof_strength(reservation_class, proof_class)?;
    let proof_ref = bounded_string_member(terms, "proof_ref", 512)?;
    if proof_ref.contains("://") && (proof_ref.contains('@') || proof_ref.contains('?')) {
        return Err("reservation proof_ref must not contain bearer-shaped URL material".into());
    }
    let capacity_commitment_sha256 = lower_hex_member(terms, "capacity_commitment_sha256")?;
    let reservation_expires_at = unsigned_member(terms, "reservation_expires_at")?;
    let mut expires_at = expiration.min(pg_i64(reservation_expires_at, "reservation_expires_at")?);
    if let Some(profile_timeout) = terms.get("profile_timeout_at") {
        let profile_timeout = profile_timeout
            .as_u64()
            .ok_or_else(|| "profile_timeout_at must be an unsigned integer".to_owned())?;
        expires_at = expires_at.min(pg_i64(profile_timeout, "profile_timeout_at")?);
    }
    let reserve_unit_sha256 = (proof_class == "covenant_reserve")
        .then(|| validate_covenant(terms, reserved_amount, reservation_expires_at))
        .transpose()?;
    Ok(MktSwpReservationClaim {
        quote_event_id: event.id.clone(),
        provider_pubkey: event.pubkey.clone(),
        session_id: session_id.to_owned(),
        rfq_event_id,
        reservation_id: reservation_id.to_owned(),
        capacity_bucket_id: Some(capacity_bucket_id.to_owned()),
        reserved_asset_id: Some(reserved_asset_id.to_owned()),
        reservation_class: reservation_class.to_owned(),
        reserved_amount,
        handler_committed_capacity,
        allocation_sequence: Some(allocation_sequence),
        proof_class: Some(proof_class.to_owned()),
        proof_strength,
        proof_ref_sha256: Some(sha256_hex(proof_ref.as_bytes())),
        reserve_unit_sha256,
        capacity_commitment_sha256: Some(capacity_commitment_sha256.to_owned()),
        expires_at: Some(expires_at),
    })
}

fn parse_status(
    event: &Event,
    session_id: &str,
    profile: &Map<String, Value>,
) -> Result<MktSwpStatusClaim, String> {
    let (counterparty_pubkey, counterparty_role) = single_role_counterparty(event)?;
    let author_role = match counterparty_role {
        "requester" => "provider",
        "provider" => "requester",
        _ => return Err("MKT-SWP Status counterparty role is invalid".to_owned()),
    };
    if counterparty_pubkey == event.pubkey {
        return Err("MKT-SWP Status parties must be distinct".to_owned());
    }
    let order_event_id = single_marked_event(event, "order")?.to_owned();
    let sequence = single_tag(event, "seq")?
        .parse::<u64>()
        .map_err(|_| "MKT-SWP Status seq must be an unsigned integer".to_owned())?;
    if sequence > MKT_SWP_MAX_STATUS_SEQUENCE {
        return Err(format!(
            "MKT-SWP Status seq exceeds {MKT_SWP_MAX_STATUS_SEQUENCE}"
        ));
    }
    let state = single_tag(event, "state")?;
    require_enum(state, MKT_STATUS_STATES, "Status state")?;
    let previous = marked_events(event, "previous");
    let previous_event_id = match (sequence, previous.as_slice()) {
        (0, []) => None,
        (0, _) => return Err("MKT-SWP Status seq 0 must not have previous".to_owned()),
        (_, [previous]) => Some((*previous).to_owned()),
        (_, _) => return Err("MKT-SWP Status seq above 0 requires one previous".to_owned()),
    };
    let swp_state = profile
        .get("swp_state")
        .and_then(Value::as_str)
        .ok_or_else(|| "MKT-SWP Status requires swp_state".to_owned())?;
    if swp_state.is_empty() || swp_state.len() > 96 || !identifier_like(swp_state) {
        return Err("MKT-SWP swp_state is invalid".to_owned());
    }
    Ok(MktSwpStatusClaim {
        status_event_id: event.id.clone(),
        author_pubkey: event.pubkey.clone(),
        author_role: author_role.to_owned(),
        counterparty_pubkey: counterparty_pubkey.to_owned(),
        session_id: session_id.to_owned(),
        order_event_id,
        sequence: i64::try_from(sequence)
            .map_err(|_| "MKT-SWP Status seq exceeds bigint".to_owned())?,
        previous_event_id,
        state: state.to_owned(),
        swp_state: swp_state.to_owned(),
    })
}

fn parse_public_evidence(
    profile: &Map<String, Value>,
    event: &Event,
) -> Result<Vec<MktSwpPublicEvidence>, String> {
    let Some(values) = profile.get("public_evidence") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| "MKT-SWP public_evidence must be an array".to_owned())?;
    if values.len() > MKT_SWP_MAX_PUBLIC_EVIDENCE_PER_RECORD {
        return Err(format!(
            "MKT-SWP public_evidence exceeds {MKT_SWP_MAX_PUBLIC_EVIDENCE_PER_RECORD} entries"
        ));
    }
    values
        .iter()
        .map(|value| parse_public_evidence_entry(value, event))
        .collect()
}

fn parse_public_evidence_entry(
    value: &Value,
    event: &Event,
) -> Result<MktSwpPublicEvidence, String> {
    validate_mkt_swp_evidence_reference(value)?;
    let evidence = value
        .as_object()
        .ok_or_else(|| "MKT-SWP public evidence must be an object".to_owned())?;
    if string_member(evidence, "class")? != "bitcoin_transaction"
        || string_member(evidence, "rail")? != "bitcoin"
        || string_member(evidence, "rung")? != "measured"
    {
        return Err(
            "public coordination hook supports measured Bitcoin transactions only".to_owned(),
        );
    }
    if string_member(evidence, "producer_pubkey")? != event.pubkey {
        return Err("public evidence producer_pubkey must match the source signer".to_owned());
    }
    if !matches!(evidence.get("verifier_pubkey"), Some(Value::Null))
        || !matches!(evidence.get("verifier_policy"), Some(Value::Null))
    {
        return Err("public evidence input must not preclaim verifier authority".to_owned());
    }
    let raw_transaction = bounded_string_member(
        evidence,
        "raw_transaction",
        MKT_SWP_MAX_PUBLIC_TRANSACTION_BYTES * 2,
    )?;
    let transaction_bytes = decode_lower_hex(raw_transaction)?;
    if transaction_bytes.is_empty()
        || transaction_bytes.len() > MKT_SWP_MAX_PUBLIC_TRANSACTION_BYTES
    {
        return Err("public transaction bytes are outside the handler bound".to_owned());
    }
    let transaction = Transaction::parse(&transaction_bytes)
        .map_err(|error| format!("public Bitcoin transaction is invalid: {error}"))?;
    let rail_reference = string_member(evidence, "reference")?;
    if lower_hex(&transaction.txid().map_err(|error| error.to_string())?) != rail_reference {
        return Err("public Bitcoin transaction ID does not match its evidence reference".into());
    }
    let artifact_sha256 = lower_hex_member(evidence, "artifact_sha256")?;
    if sha256_hex(&transaction_bytes) != artifact_sha256 {
        return Err("public Bitcoin transaction digest does not match artifact_sha256".into());
    }
    let view = bounded_string_member(evidence, "view", 512)?;
    Ok(MktSwpPublicEvidence {
        evidence_class: "bitcoin_transaction".to_owned(),
        rail_reference: rail_reference.to_owned(),
        artifact_sha256: artifact_sha256.to_owned(),
        view: view.to_owned(),
        view_sha256: sha256_hex(view.as_bytes()),
    })
}

fn validate_covenant(
    terms: &Map<String, Value>,
    reserved_amount: i64,
    reservation_expires_at: u64,
) -> Result<String, String> {
    let covenant = terms
        .get("covenant")
        .and_then(Value::as_object)
        .ok_or_else(|| "covenant_reserve requires covenant proof inputs".to_owned())?;
    let funding_ref = bounded_string_member(covenant, "funding_ref", 128)?;
    if !canonical_bitcoin_outpoint(funding_ref) {
        return Err("covenant funding_ref must be a canonical Bitcoin outpoint".to_owned());
    }
    for member in [
        "program_sha256",
        "eligible_fill_sha256",
        "fee_rule_sha256",
        "verifier_view_sha256",
    ] {
        lower_hex_member(covenant, member)?;
    }
    let minimum_output = positive_decimal_member(covenant, "minimum_output")?;
    if minimum_output < reserved_amount {
        return Err("covenant minimum_output is below the reserved amount".to_owned());
    }
    let covenant_expires_at = unsigned_member(covenant, "expires_at")?;
    if covenant_expires_at < reservation_expires_at {
        return Err("covenant expires before the reservation".to_owned());
    }
    Ok(sha256_hex(funding_ref.as_bytes()))
}

fn proof_strength(reservation: &str, proof_class: &str) -> Result<i16, String> {
    let strength = match proof_class {
        "provider_signed" if reservation == "soft" => 10,
        "handler_accounted" if matches!(reservation, "soft" | "hard") => 20,
        "third_party_guarantee" if reservation == "hard" => 40,
        "lightning_liquidity" if reservation == "hard" => 50,
        "utxo_control" if reservation == "hard" => 60,
        "funded_htlc" if reservation == "hard" => 80,
        "covenant_reserve" if reservation == "hard" => 100,
        _ => {
            return Err(
                "reservation class and proof_class are incompatible for MKT-SWP v1".to_owned(),
            );
        }
    };
    Ok(strength)
}

fn single_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, String> {
    let values = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .filter_map(|tag| tag.value())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        _ => Err(format!("MKT-SWP record requires exactly one {name} tag")),
    }
}

fn marked_events<'a>(event: &'a Event, marker: &str) -> Vec<&'a str> {
    event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .filter_map(|tag| tag.value())
        .collect()
}

fn single_marked_event<'a>(event: &'a Event, marker: &str) -> Result<&'a str, String> {
    let values = marked_events(event, marker);
    match values.as_slice() {
        [value] => Ok(value),
        _ => Err(format!(
            "MKT-SWP record requires exactly one {marker} event reference"
        )),
    }
}

fn single_counterparty<'a>(event: &'a Event, role: &str) -> Result<&'a str, String> {
    let (pubkey, actual_role) = single_role_counterparty(event)?;
    if actual_role == role {
        Ok(pubkey)
    } else {
        Err(format!("MKT-SWP record requires one {role} counterparty"))
    }
}

fn single_role_counterparty(event: &Event) -> Result<(&str, &str), String> {
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .collect::<Vec<_>>();
    let [counterparty] = counterparties.as_slice() else {
        return Err("MKT-SWP handler records require exactly one counterparty".to_owned());
    };
    let values = counterparty.as_slice();
    let pubkey = values
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| "MKT-SWP counterparty pubkey is missing".to_owned())?;
    let role = values
        .get(3)
        .map(String::as_str)
        .ok_or_else(|| "MKT-SWP counterparty role is missing".to_owned())?;
    Ok((pubkey, role))
}

fn require_enum(value: &str, allowed: &[&str], subject: &str) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{subject} is unsupported"))
    }
}

fn string_member<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("MKT-SWP coordination member {name:?} must be a string"))
}

fn bounded_string_member<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a str, String> {
    let value = string_member(object, name)?;
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(format!(
            "MKT-SWP coordination member {name:?} is empty or unbounded"
        ))
    } else {
        Ok(value)
    }
}

fn identifier_member<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    let value = bounded_string_member(object, name, 64)?;
    if identifier_like(value) {
        Ok(value)
    } else {
        Err(format!(
            "MKT-SWP coordination member {name:?} is not an identifier"
        ))
    }
}

fn identifier_like(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'0'..=b'9' => true,
        b'.' | b'_' | b'-' => index > 0,
        _ => false,
    })
}

fn asset_id_member<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    let value = bounded_string_member(object, name, 96)?;
    let mut parts = value.split(':');
    let valid = parts.next() == Some("swp")
        && parts.next() == Some("1")
        && parts.next() == Some("bip122")
        && parts.next().is_some_and(|reference| {
            reference.len() == 32
                && reference
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        && parts.next() == Some("btc")
        && parts
            .next()
            .is_some_and(|rail| matches!(rail, "chain" | "lightning"))
        && parts.next().is_none();
    if valid {
        Ok(value)
    } else {
        Err("MKT-SWP reserved_asset_id is invalid".to_owned())
    }
}

fn lower_hex_member<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    let value = string_member(object, name)?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value)
    } else {
        Err(format!(
            "MKT-SWP coordination member {name:?} must be 64 lowercase hex"
        ))
    }
}

fn decimal_member(object: &Map<String, Value>, name: &str) -> Result<i64, String> {
    let value = string_member(object, name)?;
    if !canonical_decimal(value) {
        return Err(format!(
            "MKT-SWP coordination member {name:?} must be canonical decimal"
        ));
    }
    value
        .parse::<i64>()
        .map_err(|_| format!("MKT-SWP coordination member {name:?} exceeds bigint"))
}

fn positive_decimal_member(object: &Map<String, Value>, name: &str) -> Result<i64, String> {
    let value = decimal_member(object, name)?;
    if value > 0 {
        Ok(value)
    } else {
        Err(format!(
            "MKT-SWP coordination member {name:?} must be positive"
        ))
    }
}

fn canonical_decimal(value: &str) -> bool {
    value == "0"
        || (!value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && !value.is_empty())
}

fn canonical_bitcoin_outpoint(value: &str) -> bool {
    let Some((transaction_id, output_index)) = value.split_once(':') else {
        return false;
    };
    transaction_id.len() == 64
        && transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && canonical_decimal(output_index)
        && output_index.parse::<u32>().is_ok()
}

fn unsigned_member(object: &Map<String, Value>, name: &str) -> Result<u64, String> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("MKT-SWP coordination member {name:?} must be unsigned"))
}

fn pg_i64(value: u64, field: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{field} exceeds Postgres bigint"))
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err("public transaction must be lowercase hexadecimal".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal".to_owned()),
    }
}

fn sha256_hex(value: &[u8]) -> String {
    lower_hex(&Sha256::digest(value))
}

fn lower_hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
