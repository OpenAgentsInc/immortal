//! The discovery and negotiation-preflight lab steps.
//!
//! Every step loads its inputs from and persists its outputs to the state
//! directory, so the harness can be killed after any step and restarted.

use immortal_client::{
    domain::{
        Event, MKT_OFFERING_KIND, MKT_PROVIDER_PROFILE_KIND, MKT_QUOTE_KIND, MKT_SWP_PROFILE_ID,
        MKT_SWP_PROFILE_VERSION, MktProfileSupport, validate_mkt_private_raw,
        validate_mkt_public_event,
    },
    market::{MarketSigner, unwrap_mkt_record},
    mkt_swp_client::{MktSigningRequest, SwapClientConfig, SwapRecordFactory, provider_support},
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
const LIVE_READ_WINDOW_SECONDS: u64 = 5;

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
    let identity = load_or_create_identity(paths)?;
    let signer = identity.signer()?;
    let (provider_pubkey, offering_address) = select_offering(paths)?;

    let session_id = digest(&format!(
        "immortal-lab-session:{}:{}",
        crate::util::lower_hex(&random_32()?),
        swap_type.name()
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: signer.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.clone(),
        offering_address: offering_address.clone(),
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
    let counterparty_wrap_id = relay.publish_wrapped(&rfq, &signer, &provider_pubkey)?;
    let recovery_wrap_id = relay.publish_wrapped(&rfq, &signer, signer.pubkey())?;
    relay.close();

    let session = SessionRecord {
        session_id: session_id.clone(),
        created_at: now,
        relay_url: relay_url.to_owned(),
        swap_type: swap_type.name().to_owned(),
        provider_pubkey,
        offering_address,
        step: "rfq_sent".to_owned(),
        rfq: Some(rfq.clone()),
        quote: None,
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
    let mut quote_event = stored
        .iter()
        .find_map(|wrap| match_quote(wrap, &signer, &session_id));
    if quote_event.is_none() {
        let wait = env_u64(
            "IMMORTAL_LAB_QUOTE_WAIT_SECONDS",
            DEFAULT_QUOTE_WAIT_SECONDS,
        );
        let mut waited = 0;
        while waited < wait {
            match relay.next_live_event()? {
                Some(wrap) => {
                    if let Some(event) = match_quote(&wrap, &signer, &session_id) {
                        quote_event = Some(event);
                        break;
                    }
                }
                None => waited += LIVE_READ_WINDOW_SECONDS,
            }
        }
    }
    relay.close();

    let quote_event = quote_event.ok_or_else(|| {
        format!(
            "no Quote arrived for session {session_id}; is the no-spend provider \
             running against {relay_url}? Re-run `immortal-lab quote` to keep waiting"
        )
    })?;
    session.quote = Some(quote_event.clone());
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

fn match_quote(wrap: &Event, recipient: &MarketSigner, session_id: &str) -> Option<Event> {
    match unwrap_mkt_record(wrap, recipient, &swp_profiles()) {
        Ok(delivered)
            if delivered.record.envelope.session_id == session_id
                && delivered.record.event.kind == MKT_QUOTE_KIND =>
        {
            Some(delivered.record.event)
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
    use super::*;

    #[test]
    fn fixture_profile_exists_for_every_swap_shape() {
        for swap_type in ["submarine", "reverse", "chain"] {
            let profile = fixture_profile(swap_type)
                .unwrap_or_else(|error| panic!("{swap_type} fixture profile: {error}"));
            assert!(profile.is_object(), "{swap_type} profile must be an object");
        }
    }
}
