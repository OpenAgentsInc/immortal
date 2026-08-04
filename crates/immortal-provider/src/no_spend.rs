//! Persistent no-spend provider mode.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{ErrorKind, Read},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{
    Cancellation, CloseOutcome, MktSigningRequest, StatusState, SwapClientConfig,
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND,
        MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND,
        MktProfileSupport,
    },
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record, wrap_mkt_record},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::{
    Error as WebSocketError, Message, WebSocket, client::client_with_config,
    protocol::WebSocketConfig,
};

use crate::{ProviderDiscoveryFactory, ProviderSession};

const PROVIDER_ID: &str = "immortal-no-spend";
const OFFERING_ID: &str = "immortal-no-spend-swaps";
const SUBSCRIPTION_ID: &str = "immortal-provider-inbox";
const MAX_RELAY_MESSAGE_BYTES: usize = 512 * 1024;
const MAX_HISTORY_WRAPS: usize = 120;
const MAX_SESSIONS: usize = 12;
const MAX_RECONNECT_ATTEMPTS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const QUOTE_LIFETIME_SECONDS: u64 = 600;
const FULL_SESSION_FIXTURES: &str =
    include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");

type RelaySocket = WebSocket<TcpStream>;

struct RelayClient {
    websocket: RelaySocket,
    challenge: String,
}

struct SessionActor {
    session: ProviderSession,
    requester_pubkey: String,
    rejected_reason: Option<String>,
}

struct NoSpendProvider {
    relay_url: String,
    signer: MarketSigner,
    offering_address: String,
    sessions: BTreeMap<String, SessionActor>,
}

pub fn run() -> Result<(), String> {
    let relay_url = required_environment("IMMORTAL_PROVIDER_RELAY_URL")?;
    loopback_addresses(&relay_url)?;
    let identity_secret = required_environment("IMMORTAL_PROVIDER_IDENTITY_SECRET")?;
    let signer = signer_from_lower_hex(&identity_secret)?;
    let mut provider = NoSpendProvider {
        offering_address: format!("39601:{}:{OFFERING_ID}", signer.pubkey()),
        relay_url,
        signer,
        sessions: BTreeMap::new(),
    };
    provider.run_persistent()
}

impl NoSpendProvider {
    fn run_persistent(&mut self) -> Result<(), String> {
        let mut failures = 0_usize;
        loop {
            match self.run_connection() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    failures = failures.saturating_add(1);
                    if failures > MAX_RECONNECT_ATTEMPTS {
                        return Err(format!(
                            "no-spend provider exhausted {MAX_RECONNECT_ATTEMPTS} relay reconnects: {error}"
                        ));
                    }
                    let exponent = u32::try_from(failures.saturating_sub(1).min(5))
                        .map_err(|_| "relay reconnect counter overflowed".to_owned())?;
                    let delay = Duration::from_secs(1_u64 << exponent);
                    eprintln!(
                        "immortal-provider: relay connection failed ({error}); retrying in {}s ({failures}/{MAX_RECONNECT_ATTEMPTS})",
                        delay.as_secs()
                    );
                    thread::sleep(delay);
                }
            }
        }
    }

    fn run_connection(&mut self) -> Result<(), String> {
        let now = unix_now()?;
        let mut reader = connect(&self.relay_url)?;
        authenticate(&mut reader, &self.signer, &self.relay_url, now)?;
        let mut publisher = connect(&self.relay_url)?;
        self.publish_discovery(&mut publisher, now)?;
        subscribe(&mut reader, self.signer.pubkey())?;

        let history = read_history(&mut reader)?;
        self.rebuild(history)?;
        self.republish_provider_history(&mut publisher)?;
        self.advance_all(&mut publisher)?;
        println!(
            "immortal-provider: no-spend ready relay={} pubkey={} recovered_sessions={}",
            self.relay_url,
            self.signer.pubkey(),
            self.sessions.len()
        );

        loop {
            match read_json(&mut reader.websocket) {
                Ok(message) => {
                    if let Some(wrap) = subscription_event(&message)? {
                        self.receive_wrap(wrap, &mut publisher)?;
                    }
                }
                Err(ReadError::Idle) => {
                    reader
                        .websocket
                        .send(Message::Ping(Vec::new().into()))
                        .map_err(|error| format!("could not send relay heartbeat: {error}"))?;
                }
                Err(ReadError::Closed(error)) => return Err(error),
            }
        }
    }

    fn publish_discovery(
        &self,
        publisher: &mut RelayClient,
        created_at: u64,
    ) -> Result<(), String> {
        let discovery = ProviderDiscoveryFactory::new(self.signer.pubkey())
            .map_err(|error| format!("could not initialize provider discovery: {error}"))?;
        let profile_request = discovery
            .profile(
                created_at,
                PROVIDER_ID,
                "active",
                json!({
                    "name":"Immortal no-spend provider",
                    "mode":"no_spend",
                    "settlement_claim":"coordination only; no external spend effects"
                }),
            )
            .map_err(|error| format!("could not create provider profile: {error}"))?;
        let profile = self.sign_public(profile_request)?;
        publish(publisher, &profile)?;

        let offering_request = discovery
            .offering(
                created_at,
                PROVIDER_ID,
                OFFERING_ID,
                "active",
                no_spend_offering(),
            )
            .map_err(|error| format!("could not create no-spend Offering: {error}"))?;
        let offering = self.sign_public(offering_request)?;
        publish(publisher, &offering)
    }

    fn sign_public(&self, request: crate::MktPublicSigningRequest) -> Result<Event, String> {
        let event = self.signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request
            .verify_signed(event)
            .map_err(|error| format!("provider discovery signature failed: {error}"))
    }

    fn rebuild(&mut self, wraps: Vec<Event>) -> Result<(), String> {
        let mut records = Vec::new();
        let mut seen = BTreeSet::new();
        for wrap in wraps {
            let delivered = match unwrap_mkt_record(&wrap, &self.signer, &swp_profiles()) {
                Ok(delivered) => delivered,
                Err(error) => {
                    eprintln!(
                        "immortal-provider: ignoring unreadable historical wrap {}: {error}",
                        wrap.id
                    );
                    continue;
                }
            };
            if seen.insert(delivered.record.event.id.clone()) {
                records.push(delivered.record.event);
            }
        }
        records.sort_by(|left, right| {
            recovery_rank(left, self.signer.pubkey())
                .cmp(&recovery_rank(right, self.signer.pubkey()))
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.id.cmp(&right.id))
        });

        self.sessions.clear();
        for record in records {
            let provider_authored = record.pubkey == self.signer.pubkey();
            if let Err(error) = self.ingest_record(record) {
                if provider_authored {
                    return Err(format!(
                        "provider-authored recovery history is incomplete or invalid: {error}"
                    ));
                }
                eprintln!(
                    "immortal-provider: isolating invalid requester recovery record: {error}"
                );
            }
        }
        Ok(())
    }

    fn receive_wrap(&mut self, wrap: Event, publisher: &mut RelayClient) -> Result<(), String> {
        let delivered = match unwrap_mkt_record(&wrap, &self.signer, &swp_profiles()) {
            Ok(delivered) => delivered,
            Err(error) => {
                eprintln!(
                    "immortal-provider: ignoring unreadable live wrap {}: {error}",
                    wrap.id
                );
                return Ok(());
            }
        };
        let session_id = session_id(&delivered.record.event)?.to_owned();
        let provider_authored = delivered.record.event.pubkey == self.signer.pubkey();
        if let Err(error) = self.ingest_record(delivered.record.event) {
            if provider_authored {
                return Err(format!(
                    "provider-authored live recovery record is invalid: {error}"
                ));
            }
            eprintln!("immortal-provider: rejecting session {session_id} record: {error}");
            return Ok(());
        }
        self.advance_session(&session_id, publisher)
    }

    fn ingest_record(&mut self, record: Event) -> Result<(), String> {
        let session_id = session_id(&record)?.to_owned();
        let mut inserted_session = false;
        if !self.sessions.contains_key(&session_id) {
            if record.kind != MKT_RFQ_KIND {
                return Err(format!(
                    "session {session_id} has no recoverable RFQ before kind {}",
                    record.kind
                ));
            }
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(format!("provider session bound {MAX_SESSIONS} reached"));
            }
            let offering_address = offering_reference(&record)?;
            if offering_address != self.offering_address {
                return Err("RFQ references another provider Offering".to_owned());
            }
            let config = SwapClientConfig {
                session_id: session_id.clone(),
                requester_pubkey: record.pubkey.clone(),
                provider_pubkey: self.signer.pubkey().to_owned(),
                offering_address,
            };
            let session = ProviderSession::new(config)
                .map_err(|error| format!("could not initialize session {session_id}: {error}"))?;
            self.sessions.insert(
                session_id.clone(),
                SessionActor {
                    session,
                    requester_pubkey: record.pubkey.clone(),
                    rejected_reason: None,
                },
            );
            inserted_session = true;
        }
        let result = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| "provider session disappeared".to_owned())?
            .session
            .ingest_signed(record)
            .map(|_| ())
            .map_err(|error| format!("session {session_id} rejected signed history: {error}"));
        if result.is_err() && inserted_session {
            self.sessions.remove(&session_id);
        }
        result
    }

    fn republish_provider_history(&self, publisher: &mut RelayClient) -> Result<(), String> {
        for actor in self.sessions.values() {
            for record in actor
                .session
                .signed_records()
                .iter()
                .filter(|record| record.pubkey == self.signer.pubkey())
            {
                self.publish_to_counterparty(record, &actor.requester_pubkey, publisher)?;
            }
        }
        Ok(())
    }

    fn advance_all(&mut self, publisher: &mut RelayClient) -> Result<(), String> {
        let sessions = self.sessions.keys().cloned().collect::<Vec<_>>();
        for session_id in sessions {
            self.advance_session(&session_id, publisher)?;
        }
        Ok(())
    }

    fn advance_session(
        &mut self,
        session_id: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        loop {
            let action = {
                let actor = self
                    .sessions
                    .get_mut(session_id)
                    .ok_or_else(|| format!("unknown provider session {session_id}"))?;
                if actor.rejected_reason.is_some() {
                    return Ok(());
                }
                let awaiting_quote = !has_kind_by_author(
                    actor.session.signed_records(),
                    MKT_QUOTE_KIND,
                    &actor.session.config().provider_pubkey,
                );
                match next_action(actor) {
                    Ok(action) => action,
                    Err(error) if awaiting_quote => {
                        let reason = bounded_rejection_reason(&error);
                        eprintln!(
                            "immortal-provider: rejecting incompatible no-spend session {session_id}: {reason}"
                        );
                        actor.rejected_reason = Some(reason);
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            };
            let Some(request) = action else {
                return Ok(());
            };
            let event = self.sign_private(request)?;
            let requester = self
                .sessions
                .get(session_id)
                .ok_or_else(|| "provider session disappeared before publication".to_owned())?
                .requester_pubkey
                .clone();
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| "provider session disappeared before ingestion".to_owned())?
                .session
                .ingest_signed(event.clone())
                .map_err(|error| format!("provider response failed local validation: {error}"))?;
            self.publish_record(&event, &requester, publisher)?;
        }
    }

    fn sign_private(&self, request: MktSigningRequest) -> Result<Event, String> {
        let event = self.signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request
            .verify_signed(event)
            .map_err(|error| format!("provider private signature failed: {error}"))
    }

    fn publish_record(
        &self,
        record: &Event,
        requester_pubkey: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        let raw = serde_json::to_vec(record)
            .map_err(|error| format!("could not serialize provider record: {error}"))?;
        let recovery = wrap_mkt_record(
            &raw,
            &self.signer,
            self.signer.pubkey(),
            random_wrap_material()?,
        )?;
        publish(publisher, &recovery.event)?;
        self.publish_to_counterparty(record, requester_pubkey, publisher)
    }

    fn publish_to_counterparty(
        &self,
        record: &Event,
        requester_pubkey: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        let raw = serde_json::to_vec(record)
            .map_err(|error| format!("could not serialize provider record: {error}"))?;
        let delivery = wrap_mkt_record(
            &raw,
            &self.signer,
            requester_pubkey,
            random_wrap_material()?,
        )?;
        publish(publisher, &delivery.event)
    }
}

fn next_action(actor: &mut SessionActor) -> Result<Option<MktSigningRequest>, String> {
    let records = actor.session.signed_records();
    let newest = records
        .iter()
        .map(|record| record.created_at)
        .max()
        .unwrap_or(unix_now()?);
    let created_at = unix_now()?.max(newest.saturating_add(1));
    let session_id = actor.session.config().session_id.clone();

    if !has_kind_by_author(
        records,
        MKT_QUOTE_KIND,
        &actor.session.config().provider_pubkey,
    ) {
        let rfq = exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?;
        let swap_type = rfq_swap_type(rfq)?;
        let rfq_expiration = tag_value(rfq, "expiration")
            .ok_or_else(|| "RFQ has no expiration".to_owned())?
            .parse::<u64>()
            .map_err(|_| "RFQ expiration is invalid".to_owned())?;
        if created_at >= rfq_expiration {
            return Err("RFQ expired before the no-spend Quote was created".to_owned());
        }
        let expiration = created_at
            .saturating_add(QUOTE_LIFETIME_SECONDS)
            .min(rfq_expiration);
        let profile = quote_profile(swap_type, rfq, expiration)?;
        return actor
            .session
            .soft_quote(
                created_at,
                &deterministic_id("quote", &session_id),
                expiration,
                profile,
            )
            .map(Some)
            .map_err(|error| format!("could not construct no-spend Quote: {error}"));
    }
    if !has_kind_by_author(records, MKT_ORDER_KIND, &actor.requester_pubkey) {
        return Ok(None);
    }

    let requester_contract = records.iter().find(|record| {
        record.kind == MKT_SWP_SWAP_CONTRACT_KIND && record.pubkey == actor.requester_pubkey
    });
    if requester_contract.is_none() {
        return Ok(None);
    }
    if !records.iter().any(|record| {
        record.kind == MKT_SWP_SWAP_CONTRACT_KIND
            && record.pubkey == actor.session.config().provider_pubkey
    }) {
        let contract = requester_contract
            .and_then(|record| record_profile(record).ok())
            .and_then(|profile| profile.get("contract").cloned())
            .ok_or_else(|| "requester Swap Contract has no complete contract".to_owned())?;
        return actor
            .session
            .provider_swap_contract(
                created_at,
                &deterministic_id("provider-contract", &session_id),
                None,
                contract,
            )
            .map(Some)
            .map_err(|error| format!("could not countersign requester contract: {error}"));
    }
    if !has_kind_by_author(
        records,
        MKT_STATUS_KIND,
        &actor.session.config().provider_pubkey,
    ) {
        return actor
            .session
            .provider_status(
                created_at,
                &deterministic_id("accepted-status", &session_id),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .map(Some)
            .map_err(|error| format!("could not construct provider Status: {error}"));
    }

    let cancel_request = records.iter().find(|record| {
        record.kind == MKT_CANCEL_KIND
            && record.pubkey == actor.requester_pubkey
            && tag_value(record, "action") == Some("request")
    });
    let Some(cancel_request) = cancel_request else {
        return Ok(None);
    };
    let accepted = records.iter().find(|record| {
        record.kind == MKT_CANCEL_KIND
            && record.pubkey == actor.session.config().provider_pubkey
            && tag_value(record, "action") == Some("accepted")
    });
    if accepted.is_none() {
        return actor
            .session
            .provider_cancel(
                created_at,
                &deterministic_id("cancel-accepted", &session_id),
                Cancellation {
                    action: "accepted",
                    reason: "no_spend_rehearsal",
                    request_id: Some(&cancel_request.id),
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .map(Some)
            .map_err(|error| format!("could not accept no-spend Cancel: {error}"));
    }
    let accepted = accepted.ok_or_else(|| "accepted Cancel disappeared".to_owned())?;
    let effective = records.iter().find(|record| {
        record.kind == MKT_CANCEL_KIND
            && record.pubkey == actor.session.config().provider_pubkey
            && tag_value(record, "action") == Some("effective")
    });
    if effective.is_none() {
        return actor
            .session
            .provider_cancel(
                created_at,
                &deterministic_id("cancel-effective", &session_id),
                Cancellation {
                    action: "effective",
                    reason: "no_spend_rehearsal",
                    request_id: Some(&cancel_request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .map(Some)
            .map_err(|error| format!("could not make no-spend Cancel effective: {error}"));
    }
    if has_kind_by_author(
        records,
        MKT_CLOSE_KIND,
        &actor.session.config().provider_pubkey,
    ) {
        return Ok(None);
    }
    let effective = effective.ok_or_else(|| "effective Cancel disappeared".to_owned())?;
    let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "Quote")?;
    let terms = record_profile(quote)?
        .get("terms")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "Quote has no complete terms".to_owned())?;
    let swap_type = terms
        .get("swap_type")
        .and_then(Value::as_str)
        .ok_or_else(|| "Quote has no swap type".to_owned())?;
    let output_amount = terms
        .get("output_amount")
        .and_then(Value::as_str)
        .ok_or_else(|| "Quote has no output amount".to_owned())?;
    actor
        .session
        .provider_close(
            created_at,
            &deterministic_id("cancelled-close", &session_id),
            CloseOutcome {
                outcome: "cancelled",
                terminal_at: created_at,
            },
            json!({
                "final_state":"cancelled",
                "external_spend_effects":0,
                "loss_classification":"none",
                "cancel_id":effective.id,
                "loss_accounting":zero_loss(swap_type, output_amount)
            }),
        )
        .map(Some)
        .map_err(|error| format!("could not construct zero-loss Close: {error}"))
}

fn no_spend_offering() -> Value {
    let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
    let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
    let second_chain = "swp:1:bip122:11111111111111111111111111111111:btc:chain";
    json!({
        "mkt_swp":{
            "swap_types":["submarine","reverse","chain"],
            "sides":[
                {"input_asset_id":chain,"output_asset_id":lightning,"min":"100000","max":"100000","fee_bps":"9800"},
                {"input_asset_id":lightning,"output_asset_id":chain,"min":"1000","max":"1000","fee_bps":"100"},
                {"input_asset_id":chain,"output_asset_id":second_chain,"min":"100000","max":"100000","fee_bps":"100"}
            ],
            "networks":[
                "bip122:00000000000000000000000000000000",
                "bip122:11111111111111111111111111111111"
            ],
            "script_modes":["taproot-musig2-script-exit"],
            "reservation_proof_classes":["provider_signed"],
            "confirmation_policies":[{
                "policy_id":"btc-1conf-no-rbf",
                "minimum_confirmations":"1",
                "reorg_safety_blocks":"6",
                "zero_confirmation":"forbidden",
                "rbf":"reject",
                "replacement":"reject"
            }],
            "availability":"limited",
            "evm_extension":"unsupported"
        }
    })
}

fn quote_profile(swap_type: &str, rfq: &Event, expiration: u64) -> Result<Value, String> {
    let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
        .map_err(|error| format!("full-session fixture is invalid: {error}"))?;
    let records = fixtures
        .get("flows")
        .and_then(|flows| flows.get(swap_type))
        .and_then(|flow| flow.get("snapshot"))
        .and_then(|snapshot| snapshot.get("signed_records"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no full-session fixture for {swap_type}"))?;
    let quote = records
        .iter()
        .find(|record| {
            record.get("kind").and_then(Value::as_u64) == Some(u64::from(MKT_QUOTE_KIND))
        })
        .and_then(|record| record.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("full-session fixture has no {swap_type} Quote"))?;
    let mut profile = serde_json::from_str::<Value>(quote)
        .map_err(|error| format!("fixture Quote content is invalid: {error}"))?
        .get("mkt_swp")
        .cloned()
        .ok_or_else(|| "fixture Quote has no MKT-SWP profile".to_owned())?;
    let desired_completion = record_profile(rfq)?
        .get("constraints")
        .and_then(|constraints| constraints.get("desired_completion_time"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "RFQ has no desired completion time".to_owned())?;
    profile["terms"]["desired_completion_time"] = Value::from(desired_completion);
    profile["reservation_terms"]["reservation_expires_at"] = Value::from(expiration);
    profile["reservation_terms"]["reservation_id"] =
        Value::String(deterministic_id("reservation", session_id(rfq)?));
    profile["reservation_terms"]["capacity_bucket_id"] =
        Value::String("no-spend-rehearsal".to_owned());
    profile["reservation_terms"]["proof_ref"] =
        Value::String(format!("provider-signed:no-spend:{}", session_id(rfq)?));
    profile["reservation_terms"]["capacity_commitment_sha256"] =
        Value::String(deterministic_id("capacity", session_id(rfq)?));
    Ok(profile)
}

fn zero_loss(swap_type: &str, reservation_released: &str) -> Value {
    let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
    let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
    let second_chain = "swp:1:bip122:11111111111111111111111111111111:btc:chain";
    let pair = match swap_type {
        "submarine" => [chain, lightning],
        "reverse" => [lightning, chain],
        "chain" => [chain, second_chain],
        _ => [chain, chain],
    };
    json!({
        "input_asset_id":pair[0],
        "output_asset_id":pair[1],
        "input_committed":"0",
        "input_recovered":"0",
        "output_received":"0",
        "provider_fee_paid":"0",
        "miner_fee_paid":"0",
        "lightning_routing_fee_paid":"0",
        "guarantee_recovery_received":"0",
        "principal_unresolved":"0",
        "reservation_released":reservation_released,
        "evidence_refs":[],
        "unknown_fields":[]
    })
}

fn connect(relay_url: &str) -> Result<RelayClient, String> {
    let addresses = loopback_addresses(relay_url)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay write timeout: {error}"))?;
                let config = WebSocketConfig::default()
                    .read_buffer_size(16 * 1024)
                    .write_buffer_size(0)
                    .max_write_buffer_size(MAX_RELAY_MESSAGE_BYTES)
                    .max_message_size(Some(MAX_RELAY_MESSAGE_BYTES))
                    .max_frame_size(Some(MAX_RELAY_MESSAGE_BYTES));
                let (mut websocket, _) = client_with_config(relay_url, stream, Some(config))
                    .map_err(|error| format!("could not open relay WebSocket: {error}"))?;
                let challenge_message = read_json(&mut websocket).map_err(read_error_string)?;
                let challenge = challenge_message
                    .as_array()
                    .filter(|message| message.first() == Some(&Value::String("AUTH".into())))
                    .and_then(|message| message.get(1))
                    .and_then(Value::as_str)
                    .filter(|challenge| !challenge.is_empty() && challenge.len() <= 512)
                    .ok_or_else(|| "relay did not send a bounded NIP-42 challenge".to_owned())?
                    .to_owned();
                return Ok(RelayClient {
                    websocket,
                    challenge,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "could not connect to loopback relay: {}",
        last_error.map_or_else(
            || "no resolved address".to_owned(),
            |error| error.to_string()
        )
    ))
}

fn authenticate(
    client: &mut RelayClient,
    signer: &MarketSigner,
    relay_url: &str,
    now: u64,
) -> Result<(), String> {
    let event = signer.sign(
        now,
        22_242,
        vec![
            immortal_core::domain::Tag::new(vec!["relay".into(), relay_url.into()]),
            immortal_core::domain::Tag::new(vec!["challenge".into(), client.challenge.clone()]),
        ],
        String::new(),
    );
    send_json(&mut client.websocket, json!(["AUTH", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn subscribe(client: &mut RelayClient, recipient: &str) -> Result<(), String> {
    send_json(
        &mut client.websocket,
        json!(["REQ", SUBSCRIPTION_ID, {"kinds":[1059],"#p":[recipient],"limit":MAX_HISTORY_WRAPS + 1}]),
    )
}

fn read_history(client: &mut RelayClient) -> Result<Vec<Event>, String> {
    let mut wraps = Vec::new();
    loop {
        let message = read_json(&mut client.websocket).map_err(read_error_string)?;
        if message == json!(["EOSE", SUBSCRIPTION_ID]) {
            return Ok(wraps);
        }
        let wrap = subscription_event(&message)?
            .ok_or_else(|| format!("unexpected history response: {message}"))?;
        if wraps.len() >= MAX_HISTORY_WRAPS {
            return Err(format!(
                "relay exceeded provider history bound {MAX_HISTORY_WRAPS}"
            ));
        }
        wraps.push(wrap);
    }
}

fn subscription_event(message: &Value) -> Result<Option<Event>, String> {
    let Some(fields) = message.as_array() else {
        return Err(format!("relay message is not an array: {message}"));
    };
    if fields.first().and_then(Value::as_str) != Some("EVENT") {
        return Ok(None);
    }
    if fields.get(1).and_then(Value::as_str) != Some(SUBSCRIPTION_ID) {
        return Err("relay delivered an event for another subscription".to_owned());
    }
    let event: Event = serde_json::from_value(fields.get(2).cloned().unwrap_or(Value::Null))
        .map_err(|error| format!("relay subscription payload is not an event: {error}"))?;
    Ok(Some(event))
}

fn publish(client: &mut RelayClient, event: &Event) -> Result<(), String> {
    send_json(&mut client.websocket, json!(["EVENT", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn expect_ok(websocket: &mut RelaySocket, event_id: &str) -> Result<(), String> {
    let response = read_json(websocket).map_err(read_error_string)?;
    let fields = response
        .as_array()
        .ok_or_else(|| format!("relay response is not an array: {response}"))?;
    if fields.first().and_then(Value::as_str) == Some("OK")
        && fields.get(1).and_then(Value::as_str) == Some(event_id)
        && fields.get(2).and_then(Value::as_bool) == Some(true)
    {
        Ok(())
    } else {
        Err(format!("relay rejected event {event_id}: {response}"))
    }
}

fn send_json(websocket: &mut RelaySocket, value: Value) -> Result<(), String> {
    let text = value.to_string();
    if text.len() > MAX_RELAY_MESSAGE_BYTES {
        return Err("outbound relay message exceeds its byte bound".to_owned());
    }
    websocket
        .send(Message::text(text))
        .map_err(|error| format!("could not write relay message: {error}"))
}

enum ReadError {
    Idle,
    Closed(String),
}

fn read_json(websocket: &mut RelaySocket) -> Result<Value, ReadError> {
    loop {
        match websocket.read() {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_RELAY_MESSAGE_BYTES {
                    return Err(ReadError::Closed(
                        "relay text message exceeds its byte bound".to_owned(),
                    ));
                }
                return serde_json::from_str(text.as_str()).map_err(|error| {
                    ReadError::Closed(format!("relay message is invalid JSON: {error}"))
                });
            }
            Ok(Message::Ping(payload)) => {
                websocket.send(Message::Pong(payload)).map_err(|error| {
                    ReadError::Closed(format!("could not answer relay ping: {error}"))
                })?
            }
            Ok(Message::Pong(_)) => {}
            Ok(Message::Close(_)) => {
                return Err(ReadError::Closed("relay closed the WebSocket".to_owned()));
            }
            Ok(message) => {
                return Err(ReadError::Closed(format!(
                    "unexpected relay frame: {message:?}"
                )));
            }
            Err(WebSocketError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Err(ReadError::Idle);
            }
            Err(error) => {
                return Err(ReadError::Closed(format!(
                    "could not read relay message: {error}"
                )));
            }
        }
    }
}

fn read_error_string(error: ReadError) -> String {
    match error {
        ReadError::Idle => "relay read timed out".to_owned(),
        ReadError::Closed(error) => error,
    }
}

fn loopback_addresses(relay_url: &str) -> Result<Vec<SocketAddr>, String> {
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| "no-spend provider accepts only ws:// loopback URLs".to_owned())?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || relay_url.contains('?')
        || relay_url.contains('#')
    {
        return Err("no-spend provider relay URL is invalid".to_owned());
    }
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve no-spend relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("no-spend provider refuses non-loopback relay addresses".to_owned());
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn required_environment(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn signer_from_lower_hex(secret: &str) -> Result<MarketSigner, String> {
    if secret.len() != 64
        || secret
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(
            "IMMORTAL_PROVIDER_IDENTITY_SECRET must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in secret.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    MarketSigner::from_secret_bytes(bytes)
        .map_err(|error| format!("provider identity key is invalid: {error}"))
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("provider identity key contains non-hexadecimal data".to_owned()),
    }
}

fn swp_profiles() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }]
}

fn session_id(event: &Event) -> Result<&str, String> {
    exactly_one_tag(event, "session")
}

fn offering_reference(event: &Event) -> Result<String, String> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("a") && tag.as_slice().get(3).map(String::as_str) == Some("offering")
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("RFQ requires exactly one Offering reference".to_owned());
    }
    matches[0]
        .value()
        .map(str::to_owned)
        .ok_or_else(|| "RFQ Offering reference has no address".to_owned())
}

fn exactly_one_tag<'a>(event: &'a Event, name: &'a str) -> Result<&'a str, String> {
    let values = event.tag_values(name).collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(format!("event requires exactly one {name} tag"));
    }
    Ok(values[0])
}

fn tag_value<'a>(event: &'a Event, name: &'a str) -> Option<&'a str> {
    event.tag_values(name).next()
}

fn record_profile(event: &Event) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Value>(&event.content)
        .map_err(|error| format!("MKT-SWP content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "MKT-SWP record has no profile object".to_owned())
}

fn rfq_swap_type(event: &Event) -> Result<&str, String> {
    let profile = record_profile(event)?;
    let swap_type = profile
        .get("constraints")
        .and_then(|constraints| constraints.get("swap_type"))
        .and_then(Value::as_str)
        .ok_or_else(|| "RFQ has no swap type".to_owned())?
        .to_owned();
    match swap_type.as_str() {
        "submarine" => Ok("submarine"),
        "reverse" => Ok("reverse"),
        "chain" => Ok("chain"),
        _ => Err("RFQ requests an unsupported swap type".to_owned()),
    }
}

fn has_kind_by_author(records: &[Event], kind: u16, author: &str) -> bool {
    records
        .iter()
        .any(|record| record.kind == kind && record.pubkey == author)
}

fn bounded_rejection_reason(error: &str) -> String {
    error.chars().take(256).collect()
}

fn exactly_one_kind<'a>(records: &'a [Event], kind: u16, label: &str) -> Result<&'a Event, String> {
    let matching = records
        .iter()
        .filter(|record| record.kind == kind)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!("session requires exactly one {label}"));
    }
    Ok(matching[0])
}

fn recovery_rank(event: &Event, provider_pubkey: &str) -> (u8, u64) {
    match event.kind {
        MKT_RFQ_KIND => (0, 0),
        MKT_QUOTE_KIND => (1, 0),
        MKT_ORDER_KIND => (2, 0),
        MKT_SWP_SWAP_CONTRACT_KIND if event.pubkey != provider_pubkey => (3, 0),
        MKT_SWP_SWAP_CONTRACT_KIND => (4, 0),
        MKT_STATUS_KIND => (
            5,
            tag_value(event, "seq")
                .and_then(|sequence| sequence.parse::<u64>().ok())
                .unwrap_or(u64::MAX),
        ),
        MKT_CANCEL_KIND => match tag_value(event, "action") {
            Some("request") => (6, 0),
            Some("accepted" | "rejected") => (7, 0),
            Some("effective") => (8, 0),
            _ => (9, 0),
        },
        MKT_CLOSE_KIND => (10, 0),
        _ => (u8::MAX, 0),
    }
}

fn deterministic_id(label: &str, session_id: &str) -> String {
    lower_hex(&Sha256::digest(
        format!("immortal-provider-no-spend-v1\0{label}\0{session_id}").as_bytes(),
    ))
}

fn random_wrap_material() -> Result<WrapMaterial, String> {
    let now = unix_now()?;
    Ok(WrapMaterial {
        seal_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        wrap_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        seal_nonce: random_32()?,
        wrap_nonce: random_32()?,
        wrap_secret: random_secret_bytes()?,
    })
}

fn random_secret_bytes() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate a valid one-time wrapping key".to_owned())
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{Event, MKT_CLOSE_KIND, MKT_STATUS_KIND, has_kind_by_author};

    #[test]
    fn requester_status_and_close_do_not_suppress_provider_actions() {
        let requester = "11".repeat(32);
        let provider = "22".repeat(32);
        let records = vec![
            event(MKT_STATUS_KIND, &requester),
            event(MKT_CLOSE_KIND, &requester),
        ];

        assert!(!has_kind_by_author(&records, MKT_STATUS_KIND, &provider));
        assert!(!has_kind_by_author(&records, MKT_CLOSE_KIND, &provider));
        assert!(has_kind_by_author(&records, MKT_STATUS_KIND, &requester));
        assert!(has_kind_by_author(&records, MKT_CLOSE_KIND, &requester));
    }

    fn event(kind: u16, pubkey: &str) -> Event {
        Event {
            id: "00".repeat(32),
            pubkey: pubkey.to_owned(),
            created_at: 0,
            kind,
            tags: Vec::new(),
            content: String::new(),
            sig: "00".repeat(64),
        }
    }
}
