//! The discovery and negotiation-preflight lab steps.
//!
//! Every step loads its inputs from and persists its outputs to the state
//! directory, so the harness can be killed after any step and restarted.

use std::{cmp::Ordering, collections::BTreeSet};

use immortal_client::{
    domain::{
        Event, MKT_OFFERING_KIND, MKT_PROVIDER_PROFILE_KIND, MKT_QUOTE_KIND, MKT_SWP_PROFILE_ID,
        MKT_SWP_PROFILE_VERSION, MktProfileSupport, validate_mkt_private_raw,
        validate_mkt_public_event,
    },
    market::{MarketSigner, unwrap_mkt_record_raw},
    mkt_swp_client::{
        MktSigningRequest, RequesterQuoteView, RequesterSessionView, RequesterVerificationState,
        SignedRecordDelivery, SwapClientConfig, SwapRecordFactory, provider_support,
    },
};
use serde_json::{Value, json};

use crate::{
    cli::SwapShape,
    relay::RelayClient,
    state::{
        DiscoveredOffering, DiscoveredProvider, Discovery, LabPaths, SessionRecord, list_sessions,
        load_discovery, load_funded_checkpoint, load_identity, load_or_create_identity,
        load_session, resolve_session_id, set_current_session, store_discovery, store_session,
    },
    util::{digest, random_32, unix_now},
};

/// The pinned full-session fixture corpus; the RFQ profile body for each
/// swap shape comes from here, exactly as the no-spend live smoke does it.
const FULL_SESSION_FIXTURES: &str =
    include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");

const MKT_RFQ_KIND_U64: u64 = 39_604;
const DEFAULT_RFQ_EXPIRY_SECONDS: u64 = 300;
const DEFAULT_QUOTE_WAIT_SECONDS: u64 = 30;
const MAX_TOPOLOGY_QUOTE_WAIT_SECONDS: u64 = 120;
const LIVE_READ_WINDOW_SECONDS: u64 = 5;
const TOPOLOGY_PROVIDER_COUNT: usize = 2;
const TOPOLOGY_FIXTURE: &str = include_str!("../../../tests/fixtures/lab/topology-quotes-v1.json");

/// Step 1: collect Provider Profiles and Offerings from the relay and
/// persist a discovery snapshot.
pub fn discover(paths: &LabPaths, relay_url: &str) -> Result<Value, String> {
    let mut relay = RelayClient::connect(relay_url)?;
    let events = relay.request_stored(
        "lab-discovery",
        json!({
            "kinds": [MKT_PROVIDER_PROFILE_KIND, MKT_OFFERING_KIND],
            "limit": 512
        }),
    )?;
    relay.close();

    let mut providers: Vec<DiscoveredProvider> = Vec::new();
    let mut offerings: Vec<(String, DiscoveredOffering)> = Vec::new();
    for event in &events {
        if let Err(error) = validate_mkt_public_event(event) {
            eprintln!(
                "immortal-lab discover: skipping invalid public event {}: {error}",
                event.id
            );
            continue;
        }
        let distinct = tag_value(event, "d").unwrap_or_default().to_owned();
        let status = tag_value(event, "status").unwrap_or("unknown").to_owned();
        if event.kind == MKT_PROVIDER_PROFILE_KIND {
            providers.push(DiscoveredProvider {
                pubkey: event.pubkey.clone(),
                profile_event_id: event.id.clone(),
                status,
                offerings: Vec::new(),
            });
        } else {
            offerings.push((
                event.pubkey.clone(),
                DiscoveredOffering {
                    address: format!("{MKT_OFFERING_KIND}:{}:{distinct}", event.pubkey),
                    distinct,
                    status,
                    event_id: event.id.clone(),
                },
            ));
        }
    }
    for (pubkey, offering) in offerings {
        if let Some(provider) = providers
            .iter_mut()
            .find(|provider| provider.pubkey == pubkey)
        {
            provider.offerings.push(offering);
        } else {
            eprintln!(
                "immortal-lab discover: offering {} has no provider profile; skipping",
                offering.address
            );
        }
    }

    let discovery = Discovery {
        relay_url: relay_url.to_owned(),
        discovered_at: unix_now()?,
        providers,
    };
    store_discovery(paths, &discovery)?;
    Ok(json!({
        "step": "discover",
        "relay_url": relay_url,
        "providers": discovery.providers.len(),
        "offerings": discovery
            .providers
            .iter()
            .map(|provider| provider.offerings.len())
            .sum::<usize>(),
        "state_dir": paths.root().display().to_string(),
    }))
}

/// Step 2: open a session and send the wrapped MKT-SWP RFQ, built by the
/// real client engine (`SwapRecordFactory`) from the pinned fixture profile.
pub fn rfq(paths: &LabPaths, relay_url: &str, swap_type: SwapShape) -> Result<Value, String> {
    let (provider_pubkey, offering_address) = select_offering(paths)?;
    rfq_for_offering(
        paths,
        relay_url,
        swap_type,
        &provider_pubkey,
        &offering_address,
    )
}

fn rfq_for_offering(
    paths: &LabPaths,
    relay_url: &str,
    swap_type: SwapShape,
    provider_pubkey: &str,
    offering_address: &str,
) -> Result<Value, String> {
    let identity = load_or_create_identity(paths)?;
    let signer = identity.signer()?;

    let session_id = digest(&format!(
        "immortal-lab-session:{}:{}",
        crate::util::lower_hex(&random_32()?),
        swap_type.name()
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: signer.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: offering_address.to_owned(),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config)
        .map_err(|error| format!("could not initialize the client engine: {error}"))?;
    let now = unix_now()?;
    let expiry = env_u64(
        "IMMORTAL_LAB_RFQ_EXPIRY_SECONDS",
        DEFAULT_RFQ_EXPIRY_SECONDS,
    );
    let rfq = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(expiry),
                fixture_profile(swap_type.name())?,
            )
            .map_err(|error| format!("client engine refused the RFQ: {error}"))?,
        &signer,
    )?;

    let mut relay = RelayClient::connect(relay_url)?;
    let counterparty_wrap_id = relay.publish_wrapped(&rfq, &signer, provider_pubkey)?;
    let recovery_wrap_id = relay.publish_wrapped(&rfq, &signer, signer.pubkey())?;
    relay.close();

    let session = SessionRecord {
        session_id: session_id.clone(),
        created_at: now,
        relay_url: relay_url.to_owned(),
        swap_type: swap_type.name().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: offering_address.to_owned(),
        step: "rfq_sent".to_owned(),
        rfq: Some(rfq.clone()),
        quote: None,
        quote_wrap: None,
        quote_observed_at: None,
        verification: None,
    };
    store_session(paths, &session)?;
    set_current_session(paths, &session_id)?;
    Ok(json!({
        "step": "rfq",
        "session_id": session_id,
        "swap_type": swap_type.name(),
        "rfq_id": rfq.id,
        "counterparty_wrap_id": counterparty_wrap_id,
        "recovery_wrap_id": recovery_wrap_id,
        "expires_at": now.saturating_add(expiry),
    }))
}

/// Step 3: authenticate, read the recipient-gated gift-wrap subscription
/// (stored history first, then a bounded live wait), and persist the Quote.
pub fn quote(paths: &LabPaths, relay_url: &str) -> Result<Value, String> {
    let identity = load_identity(paths)?;
    let signer = identity.signer()?;
    let session_id = resolve_session_id(paths)?;
    let mut session = load_session(paths, &session_id)?;
    if session.rfq.is_none() {
        return Err(format!("session {session_id} has no persisted RFQ"));
    }

    let mut relay = RelayClient::connect(relay_url)?;
    relay.authenticate(&signer, relay_url)?;
    let stored = relay.request_stored(
        "lab-quotes",
        json!({"kinds": [1059], "#p": [signer.pubkey()], "limit": 512}),
    )?;
    let mut quote_delivery = stored
        .iter()
        .find_map(|wrap| match_quote(wrap, &signer, &session_id));
    if quote_delivery.is_none() {
        let wait = env_u64(
            "IMMORTAL_LAB_QUOTE_WAIT_SECONDS",
            DEFAULT_QUOTE_WAIT_SECONDS,
        );
        if wait > MAX_TOPOLOGY_QUOTE_WAIT_SECONDS {
            return Err(format!(
                "Quote wait exceeds the {MAX_TOPOLOGY_QUOTE_WAIT_SECONDS}-second lab bound"
            ));
        }
        let mut waited = 0;
        while waited < wait {
            match relay.next_live_event()? {
                Some(wrap) => {
                    if let Some(delivery) = match_quote(&wrap, &signer, &session_id) {
                        quote_delivery = Some(delivery);
                        break;
                    }
                }
                None => waited += LIVE_READ_WINDOW_SECONDS,
            }
        }
    }
    relay.close();

    let (quote_event, quote_wrap) = quote_delivery.ok_or_else(|| {
        format!(
            "no Quote arrived for session {session_id}; is the no-spend provider \
             running against {relay_url}? Re-run `immortal-lab quote` to keep waiting"
        )
    })?;
    let observed_at = unix_now()?;
    session.quote = Some(quote_event.clone());
    session.quote_wrap = Some(quote_wrap);
    session.quote_observed_at = Some(observed_at);
    session.step = "quote_received".to_owned();
    store_session(paths, &session)?;
    Ok(json!({
        "step": "quote",
        "session_id": session_id,
        "quote_id": quote_event.id,
        "quote_class": tag_value(&quote_event, "quote"),
        "reservation_class": tag_value(&quote_event, "reservation"),
        "expiration": tag_value(&quote_event, "expiration"),
    }))
}

pub fn topology_quotes(paths: &LabPaths, relay_urls: &[String]) -> Result<Value, String> {
    validate_topology_fixture()?;
    if relay_urls.len() != TOPOLOGY_PROVIDER_COUNT {
        return Err(format!(
            "topology Quote comparison requires exactly {TOPOLOGY_PROVIDER_COUNT} relays"
        ));
    }

    let mut provider_pubkeys = BTreeSet::new();
    let mut session_ids = Vec::with_capacity(TOPOLOGY_PROVIDER_COUNT);
    for relay_url in relay_urls {
        discover(paths, relay_url)?;
        let (provider_pubkey, offering_address) = sole_active_offering(paths)?;
        if !provider_pubkeys.insert(provider_pubkey.clone()) {
            return Err("topology relays advertised the same provider key".to_owned());
        }
        let result = rfq_for_offering(
            paths,
            relay_url,
            SwapShape::Submarine,
            &provider_pubkey,
            &offering_address,
        )?;
        let session_id = result
            .get("session_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "RFQ step did not return its session ID".to_owned())?
            .to_owned();
        quote(paths, relay_url)?;
        session_ids.push(session_id);
    }

    compare_topology_quotes(paths, &session_ids)
}

struct TopologyQuoteCandidate {
    session_id: String,
    relay_url: String,
    offering_address: String,
    quote: RequesterQuoteView,
    output_amount: u64,
    maximum_total_fee: u64,
}

fn compare_topology_quotes(paths: &LabPaths, session_ids: &[String]) -> Result<Value, String> {
    if session_ids.len() != TOPOLOGY_PROVIDER_COUNT {
        return Err(format!(
            "topology Quote comparison requires exactly {TOPOLOGY_PROVIDER_COUNT} sessions"
        ));
    }
    let signer = load_identity(paths)?.signer()?;
    let observed_at = unix_now()?;
    let mut relay_urls = BTreeSet::new();
    let mut provider_pubkeys = BTreeSet::new();
    let mut candidates = Vec::with_capacity(TOPOLOGY_PROVIDER_COUNT);
    for session_id in session_ids {
        let session = load_session(paths, session_id)?;
        if !relay_urls.insert(session.relay_url.clone()) {
            return Err("topology Quote sessions must come from distinct relays".to_owned());
        }
        if !provider_pubkeys.insert(session.provider_pubkey.clone()) {
            return Err("topology Quote sessions must come from distinct providers".to_owned());
        }
        let quote = requester_quote_view(&session, &signer)?;
        if quote.quote_class != "firm"
            || !matches!(quote.reservation_class.as_str(), "soft" | "hard")
        {
            return Err("topology candidate is not a firm reserved Quote".to_owned());
        }
        if observed_at > quote.effective_acceptance_deadline {
            return Err(format!(
                "topology candidate {} expired before comparison",
                quote.quote_id
            ));
        }
        let output_amount = quote
            .output_amount
            .parse::<u64>()
            .map_err(|_| "validated Quote output amount exceeds the v1 range".to_owned())?;
        let maximum_total_fee = quote
            .fees
            .maximum_total_fee
            .parse::<u64>()
            .map_err(|_| "validated Quote fee exceeds the v1 range".to_owned())?;
        candidates.push(TopologyQuoteCandidate {
            session_id: session.session_id,
            relay_url: session.relay_url,
            offering_address: session.offering_address,
            quote,
            output_amount,
            maximum_total_fee,
        });
    }

    let baseline = candidates
        .first()
        .ok_or_else(|| "topology comparison has no candidates".to_owned())?;
    for candidate in candidates.iter().skip(1) {
        require_comparable_quotes(&baseline.quote, &candidate.quote)?;
    }
    candidates.sort_by(compare_candidate_rank);

    let selected = candidates
        .first()
        .ok_or_else(|| "topology comparison has no selected Quote".to_owned())?;
    let candidate_records = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            json!({
                "rank": index + 1,
                "relay_url": candidate.relay_url,
                "provider_pubkey": candidate.quote.provider_pubkey,
                "offering_address": candidate.offering_address,
                "session_id": candidate.session_id,
                "rfq_id": candidate.quote.rfq_id,
                "quote_id": candidate.quote.quote_id,
                "swap_type": candidate.quote.swap_type,
                "reservation_class": candidate.quote.reservation_class,
                "input_asset_id": candidate.quote.input_asset_id,
                "output_asset_id": candidate.quote.output_asset_id,
                "input_amount": candidate.quote.input_amount,
                "output_amount": candidate.quote.output_amount,
                "maximum_total_fee": candidate.quote.fees.maximum_total_fee,
                "effective_acceptance_deadline": candidate.quote.effective_acceptance_deadline,
            })
        })
        .collect::<Vec<_>>();
    let result = json!({
        "schema": "openagents.immortal.lab-topology-quote-selection.v1",
        "observed_at": observed_at,
        "wallet": {
            "pubkey": signer.pubkey(),
            "relay_count": relay_urls.len(),
            "provider_count": provider_pubkeys.len(),
        },
        "candidates": candidate_records,
        "selection": {
            "policy": [
                "output_amount_desc",
                "maximum_total_fee_asc",
                "provider_pubkey_asc",
                "quote_id_asc"
            ],
            "selected_provider_pubkey": selected.quote.provider_pubkey,
            "selected_quote_id": selected.quote.quote_id,
        }
    });
    provider_support::reject_custody_material(&result)
        .map_err(|error| format!("topology record is not custody-free: {error}"))?;
    Ok(result)
}

fn requester_quote_view(
    session: &SessionRecord,
    signer: &MarketSigner,
) -> Result<RequesterQuoteView, String> {
    let rfq = session
        .rfq
        .clone()
        .ok_or_else(|| format!("session {} has no persisted RFQ", session.session_id))?;
    let quote = session
        .quote
        .clone()
        .ok_or_else(|| format!("session {} has no persisted Quote", session.session_id))?;
    let wrap = session
        .quote_wrap
        .as_ref()
        .ok_or_else(|| format!("session {} has no exact Quote wrap", session.session_id))?;
    let raw_wrap = serde_json::to_vec(wrap)
        .map_err(|error| format!("could not serialize persisted Quote wrap: {error}"))?;
    let delivered = unwrap_mkt_record_raw(&raw_wrap, signer, &swp_profiles())
        .map_err(|error| format!("persisted Quote wrap no longer unwraps: {error}"))?;
    if delivered.record().event() != &quote {
        return Err("persisted Quote differs from its exact gift-wrap delivery".to_owned());
    }
    let rfq_delivery = SignedRecordDelivery::from_locally_signed(
        serde_json::to_vec(&rfq)
            .map_err(|error| format!("could not serialize persisted RFQ: {error}"))?,
        session.created_at,
    )
    .map_err(|error| format!("persisted RFQ delivery is invalid: {error}"))?;
    let quote_delivery = SignedRecordDelivery::from_delivered(
        &delivered,
        session.quote_observed_at.ok_or_else(|| {
            format!(
                "session {} has no Quote observation time",
                session.session_id
            )
        })?,
    )
    .map_err(|error| format!("persisted Quote delivery is invalid: {error}"))?;
    let config = SwapClientConfig {
        session_id: session.session_id.clone(),
        requester_pubkey: signer.pubkey().to_owned(),
        provider_pubkey: session.provider_pubkey.clone(),
        offering_address: session.offering_address.clone(),
        provider_route: None,
    };
    let view = RequesterSessionView::from_signed_records(
        &config,
        &[rfq, quote],
        vec![rfq_delivery, quote_delivery],
    )
    .map_err(|error| format!("requester engine rejected a topology candidate: {error}"))?;
    if view.verification.state != RequesterVerificationState::QuoteVerified
        || view.verification.funding_authorized
    {
        return Err("Quote-only requester view reported an invalid execution state".to_owned());
    }
    Ok(view.quote)
}

fn require_comparable_quotes(
    baseline: &RequesterQuoteView,
    candidate: &RequesterQuoteView,
) -> Result<(), String> {
    if baseline.swap_type != candidate.swap_type
        || baseline.input_asset_id != candidate.input_asset_id
        || baseline.output_asset_id != candidate.output_asset_id
        || baseline.input_amount != candidate.input_amount
        || baseline.amount_equation != candidate.amount_equation
        || baseline.rounding != candidate.rounding
    {
        return Err("provider Quotes are not economically comparable".to_owned());
    }
    Ok(())
}

fn compare_candidate_rank(
    left: &TopologyQuoteCandidate,
    right: &TopologyQuoteCandidate,
) -> Ordering {
    right
        .output_amount
        .cmp(&left.output_amount)
        .then_with(|| left.maximum_total_fee.cmp(&right.maximum_total_fee))
        .then_with(|| left.quote.provider_pubkey.cmp(&right.quote.provider_pubkey))
        .then_with(|| left.quote.quote_id.cmp(&right.quote.quote_id))
}

fn validate_topology_fixture() -> Result<(), String> {
    let fixture: Value = serde_json::from_str(TOPOLOGY_FIXTURE)
        .map_err(|error| format!("topology Quote fixture is invalid: {error}"))?;
    if fixture.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.lab-topology-quotes.v1")
        || fixture
            .pointer("/topology/relay_count")
            .and_then(Value::as_u64)
            != Some(TOPOLOGY_PROVIDER_COUNT as u64)
        || fixture
            .pointer("/topology/provider_count")
            .and_then(Value::as_u64)
            != Some(TOPOLOGY_PROVIDER_COUNT as u64)
        || fixture.pointer("/quote_comparison/ordering")
            != Some(&json!([
                "output_amount_desc",
                "maximum_total_fee_asc",
                "provider_pubkey_asc",
                "quote_id_asc"
            ]))
    {
        return Err("topology Quote fixture does not match the executable policy".to_owned());
    }
    Ok(())
}

/// Step 4: the verify-before-fund gate, rendered from the client engine's
/// real verification output over the persisted RFQ and Quote.
pub fn verify(paths: &LabPaths) -> Result<Value, String> {
    let session_id = resolve_session_id(paths)?;
    let mut session = load_session(paths, &session_id)?;
    let rfq = session
        .rfq
        .clone()
        .ok_or_else(|| format!("session {session_id} has no persisted RFQ"))?;
    let quote = session
        .quote
        .clone()
        .ok_or_else(|| format!("session {session_id} has no persisted Quote"))?;
    let now = unix_now()?;

    let mut checks = Vec::new();
    let mut passed = true;
    let mut record = |name: &str, result: Result<String, String>, passed: &mut bool| {
        let entry = match result {
            Ok(detail) => json!({"check": name, "result": "pass", "detail": detail}),
            Err(error) => {
                *passed = false;
                json!({"check": name, "result": "fail", "detail": error})
            }
        };
        checks.push(entry);
    };

    // 1. Structural revalidation of the persisted signed Quote bytes.
    let raw_quote = serde_json::to_vec(&quote)
        .map_err(|error| format!("could not serialize persisted Quote: {error}"))?;
    record(
        "quote_record_structure_and_signature",
        validate_mkt_private_raw(&raw_quote, &swp_profiles())
            .map(|_| "persisted Quote revalidates as a signed MKT-SWP private record".to_owned())
            .map_err(|error| error.to_string()),
        &mut passed,
    );

    // 2. Quote grammar surface: class, reservation, expiration tags.
    let quote_class = tag_value(&quote, "quote").unwrap_or_default().to_owned();
    let reservation_class = tag_value(&quote, "reservation")
        .unwrap_or_default()
        .to_owned();
    let expiration = tag_value(&quote, "expiration").and_then(|value| value.parse::<u64>().ok());
    record(
        "quote_tags",
        if quote_class.is_empty() || reservation_class.is_empty() || expiration.is_none() {
            Err("Quote is missing quote/reservation/expiration tags".to_owned())
        } else {
            Ok(format!(
                "quote_class={quote_class} reservation_class={reservation_class} \
                 expiration={}",
                expiration.unwrap_or_default()
            ))
        },
        &mut passed,
    );
    let expiration = expiration.unwrap_or_default();

    // 3. Staleness: a stale quote must fail the gate, not be funded.
    record(
        "quote_freshness",
        if now > expiration {
            Err(format!(
                "Quote expired at {expiration}; local clock is {now}"
            ))
        } else {
            Ok(format!("Quote is live until {expiration} (now {now})"))
        },
        &mut passed,
    );

    // 4 + 5. The client engine's own profile and cross-record validation.
    let profile = quote_profile(&quote);
    match &profile {
        Ok(profile_value) => {
            record(
                "engine_quote_profile",
                provider_support::validate_quote_profile(profile_value, &reservation_class)
                    .map(|_| "client engine accepts the Quote profile".to_owned())
                    .map_err(|error| error.to_string()),
                &mut passed,
            );
            record(
                "engine_quote_against_rfq",
                provider_support::validate_quote_against_rfq(
                    &rfq,
                    profile_value,
                    &quote_class,
                    quote.created_at,
                    expiration,
                )
                .map(|_| "client engine accepts the Quote against the persisted RFQ".to_owned())
                .map_err(|error| error.to_string()),
                &mut passed,
            );
        }
        Err(error) => {
            record(
                "engine_quote_profile",
                Err(format!("Quote has no MKT-SWP profile: {error}")),
                &mut passed,
            );
        }
    }

    let verdict = json!({
        "step": "verify",
        "session_id": session_id,
        "swap_type": session.swap_type,
        "rfq_id": rfq.id,
        "quote_id": quote.id,
        "overall": if passed { "pass" } else { "fail" },
        "gate": if passed {
            "verify-before-fund gate OPEN"
        } else {
            "verify-before-fund gate CLOSED: do not fund"
        },
        "checks": checks,
        "verified_at": now,
    });
    session.verification = Some(verdict.clone());
    session.step = if passed {
        "verified".to_owned()
    } else {
        "verification_failed".to_owned()
    };
    store_session(paths, &session)?;
    if passed {
        Ok(verdict)
    } else {
        Err(verdict.to_string())
    }
}

/// Print the persisted lab state.
pub fn status(paths: &LabPaths) -> Result<Value, String> {
    let identity_pubkey = if paths.identity().exists() {
        Some(load_identity(paths)?.pubkey)
    } else {
        None
    };
    let discovery = if paths.discovery().exists() {
        let discovery = load_discovery(paths)?;
        Some(json!({
            "relay_url": discovery.relay_url,
            "discovered_at": discovery.discovered_at,
            "providers": discovery.providers.len(),
        }))
    } else {
        None
    };
    let sessions = list_sessions(paths)?
        .into_iter()
        .map(|session| {
            json!({
                "session_id": session.session_id,
                "swap_type": session.swap_type,
                "step": session.step,
                "provider_pubkey": session.provider_pubkey,
                "created_at": session.created_at,
            })
        })
        .collect::<Vec<_>>();
    let funded_checkpoint = load_funded_checkpoint(paths)?;
    Ok(json!({
        "state_dir": paths.root().display().to_string(),
        "identity_pubkey": identity_pubkey,
        "discovery": discovery,
        "sessions": sessions,
        "funded_steps": ["fund", "claim", "refund"],
        "funded_checkpoint": funded_checkpoint,
    }))
}

fn select_offering(paths: &LabPaths) -> Result<(String, String), String> {
    if let (Ok(pubkey), Ok(address)) = (
        std::env::var("IMMORTAL_LAB_PROVIDER_PUBKEY"),
        std::env::var("IMMORTAL_LAB_OFFERING_ADDRESS"),
    ) {
        return Ok((pubkey, address));
    }
    let discovery = load_discovery(paths)?;
    for provider in &discovery.providers {
        if provider.status != "active" {
            continue;
        }
        if let Some(offering) = provider
            .offerings
            .iter()
            .find(|offering| offering.status == "active")
        {
            return Ok((provider.pubkey.clone(), offering.address.clone()));
        }
    }
    Err("discovery found no active provider with an active offering".to_owned())
}

fn sole_active_offering(paths: &LabPaths) -> Result<(String, String), String> {
    let discovery = load_discovery(paths)?;
    let active = discovery
        .providers
        .iter()
        .filter(|provider| provider.status == "active")
        .flat_map(|provider| {
            provider
                .offerings
                .iter()
                .filter(|offering| offering.status == "active")
                .map(|offering| (provider.pubkey.clone(), offering.address.clone()))
        })
        .collect::<Vec<_>>();
    match active.as_slice() {
        [selection] => Ok(selection.clone()),
        _ => Err(format!(
            "topology relay {} must advertise exactly one active provider Offering; found {}",
            discovery.relay_url,
            active.len()
        )),
    }
}

fn match_quote(wrap: &Event, recipient: &MarketSigner, session_id: &str) -> Option<(Event, Event)> {
    let raw_wrap = match serde_json::to_vec(wrap) {
        Ok(raw_wrap) => raw_wrap,
        Err(error) => {
            eprintln!(
                "immortal-lab quote: rejecting unserializable wrap {}: {error}",
                wrap.id
            );
            return None;
        }
    };
    match unwrap_mkt_record_raw(&raw_wrap, recipient, &swp_profiles()) {
        Ok(delivered)
            if delivered.record().envelope().session_id == session_id
                && delivered.record().event().kind == MKT_QUOTE_KIND =>
        {
            Some((delivered.record().event().clone(), wrap.clone()))
        }
        Ok(_) => None,
        Err(error) => {
            eprintln!(
                "immortal-lab quote: rejecting undecodable wrap {}: {error}",
                wrap.id
            );
            None
        }
    }
}

fn quote_profile(quote: &Event) -> Result<Value, String> {
    serde_json::from_str::<Value>(&quote.content)
        .map_err(|error| format!("Quote content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .cloned()
        .ok_or_else(|| "Quote content has no mkt_swp member".to_owned())
}

fn sign_request(request: MktSigningRequest, signer: &MarketSigner) -> Result<Event, String> {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request
        .verify_signed(event)
        .map_err(|error| format!("engine signing round-trip failed: {error}"))
}

fn fixture_profile(swap_type: &str) -> Result<Value, String> {
    let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
        .map_err(|error| format!("full-session fixture is invalid: {error}"))?;
    let records = fixtures
        .get("flows")
        .and_then(|flows| flows.get(swap_type))
        .and_then(|flow| flow.get("snapshot"))
        .and_then(|snapshot| snapshot.get("signed_records"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("full-session fixture has no {swap_type} records"))?;
    let content = records
        .iter()
        .find(|record| record.get("kind").and_then(Value::as_u64) == Some(MKT_RFQ_KIND_U64))
        .and_then(|record| record.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("full-session fixture has no {swap_type} RFQ record"))?;
    serde_json::from_str::<Value>(content)
        .map_err(|error| format!("fixture RFQ record is invalid JSON: {error}"))?
        .get("mkt_swp")
        .cloned()
        .ok_or_else(|| "fixture RFQ record has no MKT-SWP profile".to_owned())
}

fn swp_profiles() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }]
}

fn tag_value<'event>(event: &'event Event, name: &'event str) -> Option<&'event str> {
    event.tag_values(name).next()
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use immortal_client::mkt_swp_client::{RequesterFeeView, SwapType};

    use super::*;

    fn candidate(output: u64, fee: u64, provider: &str, quote_id: &str) -> TopologyQuoteCandidate {
        TopologyQuoteCandidate {
            session_id: "11".repeat(32),
            relay_url: "ws://127.0.0.1:18080".to_owned(),
            offering_address: format!("39601:{provider}:offering"),
            quote: RequesterQuoteView {
                rfq_id: "22".repeat(32),
                quote_id: quote_id.to_owned(),
                provider_pubkey: provider.to_owned(),
                quote_class: "firm".to_owned(),
                reservation_class: "soft".to_owned(),
                swap_type: SwapType::Submarine,
                input_asset_id: "swp:1:regtest:btc:chain".to_owned(),
                output_asset_id: "swp:1:regtest:btc:lightning".to_owned(),
                input_amount: "100000".to_owned(),
                output_amount: output.to_string(),
                amount_equation: "input_minus_provider_and_quoted_fees".to_owned(),
                rounding: "floor_output_sats".to_owned(),
                clock_skew_seconds: "60".to_owned(),
                expires_at: 1_000,
                effective_acceptance_deadline: 900,
                fees: RequesterFeeView {
                    fee_bps: "10".to_owned(),
                    provider_fee: "100".to_owned(),
                    miner_fee_budget: "100".to_owned(),
                    lightning_routing_fee_budget: "0".to_owned(),
                    maximum_total_fee: fee.to_string(),
                    fee_payer: "requester".to_owned(),
                },
                price_feed: None,
            },
            output_amount: output,
            maximum_total_fee: fee,
        }
    }

    #[test]
    fn topology_fixture_matches_the_executable_policy() {
        validate_topology_fixture().expect("topology fixture should match the executable policy");
    }

    #[test]
    fn topology_quote_ranking_is_order_independent_and_has_total_ties() {
        let provider_a = "11".repeat(32);
        let provider_b = "22".repeat(32);
        let mut ranked = [
            candidate(99_000, 1_000, &provider_b, &"44".repeat(32)),
            candidate(99_001, 999, &provider_a, &"33".repeat(32)),
        ];
        ranked.sort_by(compare_candidate_rank);
        assert_eq!(
            ranked
                .first()
                .expect("ranked Quotes should not be empty")
                .quote
                .provider_pubkey,
            provider_a
        );

        let mut tied = [
            candidate(99_000, 1_000, &provider_b, &"22".repeat(32)),
            candidate(99_000, 1_000, &provider_a, &"44".repeat(32)),
        ];
        tied.reverse();
        tied.sort_by(compare_candidate_rank);
        assert_eq!(
            tied.first()
                .expect("tied Quotes should not be empty")
                .quote
                .provider_pubkey,
            provider_a
        );
    }

    #[test]
    fn fixture_profile_exists_for_every_swap_shape() {
        for swap_type in ["submarine", "reverse", "chain"] {
            let profile = fixture_profile(swap_type)
                .unwrap_or_else(|error| panic!("{swap_type} fixture profile: {error}"));
            assert!(profile.is_object(), "{swap_type} profile must be an object");
        }
    }
}
