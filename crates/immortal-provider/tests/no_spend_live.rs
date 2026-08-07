use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{
    MktSigningRequest, ParticipantRole, SwapClientConfig, SwapRecordFactory,
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_OFFERING_KIND, MKT_PROVIDER_PROFILE_KIND,
        MKT_QUOTE_KIND, MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
        MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport, Tag,
    },
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record, wrap_mkt_record},
};
use immortal_provider::ProviderSession;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::{Message, WebSocket, client};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_SECRET_BYTE: u8 = 2;
const OFFERING_ID: &str = "immortal-no-spend-swaps";
const FULL_SESSION_FIXTURES: &str =
    include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");

type RelaySocket = WebSocket<TcpStream>;

struct RelayClient {
    websocket: RelaySocket,
    challenge: String,
}

struct ProviderProcess {
    child: Child,
}

impl ProviderProcess {
    fn start(relay_url: &str) -> Result<Self, String> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_immortal-provider"))
            .arg("--no-spend")
            .env(
                "IMMORTAL_PROVIDER_IDENTITY_SECRET",
                format!("{PROVIDER_SECRET_BYTE:02x}").repeat(32),
            )
            .env("IMMORTAL_PROVIDER_RELAY_URL", relay_url)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("could not launch provider process: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "provider stdout pipe is missing".to_owned())?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let result = reader
                .read_line(&mut line)
                .map(|_| line)
                .map_err(|error| error.to_string());
            if sender.send(result).is_err() {
                eprintln!("provider readiness receiver was dropped");
            }
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!("could not drain provider output after readiness: {error}");
                        break;
                    }
                }
            }
        });
        match receiver.recv_timeout(Duration::from_secs(15)) {
            Ok(Ok(line)) if line.contains("no-spend ready") => Ok(Self { child }),
            Ok(Ok(line)) => {
                stop_child(&mut child);
                Err(format!(
                    "provider emitted an unexpected readiness line: {line}"
                ))
            }
            Ok(Err(error)) => {
                stop_child(&mut child);
                Err(format!("could not read provider readiness: {error}"))
            }
            Err(error) => {
                stop_child(&mut child);
                Err(format!("provider did not become ready: {error}"))
            }
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("provider exited before stop with {status}"));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("could not inspect provider process: {error}")),
        }
        self.child
            .kill()
            .map_err(|error| format!("could not stop provider process: {error}"))?;
        self.child
            .wait()
            .map_err(|error| format!("could not reap provider process: {error}"))?;
        Ok(())
    }
}

impl Drop for ProviderProcess {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.child.kill() {
                    eprintln!("could not stop provider after live smoke: {error}");
                }
                if let Err(error) = self.child.wait() {
                    eprintln!("could not reap provider after live smoke: {error}");
                }
            }
            Err(error) => eprintln!("could not inspect provider after live smoke: {error}"),
        }
    }
}

#[test]
#[ignore = "requires a loopback Immortal relay; run scripts/test-dev-market-provider.sh"]
fn separate_no_spend_daemon_recovers_and_completes_all_swap_shapes() {
    run_live_smoke().expect("no-spend live smoke failed");
}

#[test]
#[ignore = "requires scripts/dev-no-spend-demo.sh; run scripts/test-dev-no-spend-demo.sh"]
fn two_provider_demo_manifest_quotes_restart_and_close_are_live() {
    run_two_provider_demo_smoke().expect("two-provider demo smoke failed");
}

fn run_live_smoke() -> Result<(), String> {
    let relay_url = std::env::var("IMMORTAL_PROVIDER_LIVE_RELAY_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:18080".to_owned());
    let provider_signer = MarketSigner::from_secret_bytes([PROVIDER_SECRET_BYTE; 32])?;
    let provider_pubkey = provider_signer.pubkey().to_owned();
    let mut provider = ProviderProcess::start(&relay_url)?;

    publish_incompatible_rfq(&relay_url, &provider_pubkey)?;

    for (index, swap_type) in ["submarine", "reverse", "chain"].into_iter().enumerate() {
        let restart_after_order = index == 0;
        drive_flow(
            &relay_url,
            &provider_pubkey,
            u8::try_from(10 + index).map_err(|_| "requester key index overflowed".to_owned())?,
            swap_type,
            restart_after_order,
            &mut provider,
        )?;
    }
    provider.stop()?;
    Ok(())
}

#[derive(Debug)]
struct FlowReceipt {
    requester_pubkey: String,
    provider_pubkey: String,
    quote_id: String,
    quote_lifetime_seconds: u64,
    desired_completion_time: u64,
    output_amount: String,
    maximum_total_fee: String,
    close_id: String,
}

fn run_two_provider_demo_smoke() -> Result<(), String> {
    let manifest_path = std::env::var("IMMORTAL_DEMO_MANIFEST")
        .map_err(|_| "IMMORTAL_DEMO_MANIFEST is required".to_owned())?;
    let control_dir = std::env::var("IMMORTAL_DEMO_CONTROL_DIR")
        .map_err(|_| "IMMORTAL_DEMO_CONTROL_DIR is required".to_owned())?;
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("could not read demo manifest: {error}"))?;
    if manifest_bytes.len() > 32_768 {
        return Err("demo manifest exceeds its public bound".to_owned());
    }
    let raw_manifest = String::from_utf8(manifest_bytes)
        .map_err(|error| format!("demo manifest is not UTF-8: {error}"))?;
    for forbidden in [
        "identity_secret",
        "provider-a.secret",
        "provider-b.secret",
        "private_key",
        "preimage",
        "macaroon",
    ] {
        if raw_manifest.to_ascii_lowercase().contains(forbidden) {
            return Err(format!(
                "public demo manifest contains forbidden {forbidden}"
            ));
        }
    }
    let manifest: Value = serde_json::from_str(&raw_manifest)
        .map_err(|error| format!("demo manifest is invalid JSON: {error}"))?;
    if manifest.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.no-spend-demo-manifest.v1")
        || manifest.get("mode").and_then(Value::as_str) != Some("no_spend")
        || manifest
            .pointer("/lifecycle/external_spend_effects")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err("demo manifest contract is invalid".to_owned());
    }
    let relay_url = manifest
        .pointer("/relay/websocket_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "demo manifest omits relay WebSocket URL".to_owned())?;
    loopback_addresses(relay_url)?;
    let provider_a = demo_provider(&manifest, "provider-a")?;
    let provider_b = demo_provider(&manifest, "provider-b")?;
    if provider_a.0 == provider_b.0 || provider_a.1 == provider_b.1 {
        return Err("demo providers do not have distinct identities and Offerings".to_owned());
    }
    verify_demo_discovery(relay_url, &[&provider_a, &provider_b])?;

    let manifest_path_for_restart = manifest_path.clone();
    let provider_a_pubkey = provider_a.0.clone();
    let provider_b_pubkey = provider_b.0.clone();
    let mut restart = move || {
        fs::write(
            Path::new(&control_dir).join("restart-provider-a"),
            b"restart\n",
        )
        .map_err(|error| format!("could not request provider-a restart: {error}"))?;
        for _ in 0..300 {
            let current: Value = serde_json::from_slice(
                &fs::read(&manifest_path_for_restart)
                    .map_err(|error| format!("could not reread demo manifest: {error}"))?,
            )
            .map_err(|error| format!("updated demo manifest is invalid: {error}"))?;
            let current_a = demo_provider(&current, "provider-a")?;
            let current_b = demo_provider(&current, "provider-b")?;
            let a_restarts = demo_restart_count(&current, "provider-a")?;
            let b_restarts = demo_restart_count(&current, "provider-b")?;
            let a_ready = demo_health_state(&current, "provider-a")? == "ready";
            let b_ready = demo_health_state(&current, "provider-b")? == "ready";
            if a_restarts >= 1 && a_ready && b_ready {
                if current_a.0 != provider_a_pubkey || current_b.0 != provider_b_pubkey {
                    return Err("provider identity changed across supervised restart".to_owned());
                }
                if b_restarts != 0 {
                    return Err("provider-b restarted while provider-a recovered".to_owned());
                }
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("provider-a did not recover its in-flight session in time".to_owned())
    };
    let a = drive_flow_with_restart(
        relay_url,
        &provider_a.0,
        &provider_a.1,
        31,
        "submarine",
        "demo-provider-a",
        Some(&mut restart),
    )?;
    let b = drive_flow_with_restart(
        relay_url,
        &provider_b.0,
        &provider_b.1,
        31,
        "submarine",
        "demo-provider-b",
        None,
    )?;
    if a.requester_pubkey != b.requester_pubkey
        || a.provider_pubkey == b.provider_pubkey
        || a.quote_id == b.quote_id
        || a.quote_lifetime_seconds == b.quote_lifetime_seconds
        || a.desired_completion_time == b.desired_completion_time
    {
        return Err(
            "demo Quotes are not independently attributable and policy-distinct".to_owned(),
        );
    }
    println!(
        "{}",
        json!({
            "schema":"openagents.immortal.no-spend-demo-smoke.v1",
            "relay_url":relay_url,
            "requester_pubkey":a.requester_pubkey,
            "providers":[
                {
                    "pubkey":a.provider_pubkey,
                    "quote_id":a.quote_id,
                    "quote_lifetime_seconds":a.quote_lifetime_seconds,
                    "desired_completion_time":a.desired_completion_time,
                    "output_amount":a.output_amount,
                    "maximum_total_fee":a.maximum_total_fee,
                    "close_id":a.close_id,
                    "restart_count":demo_restart_count(&serde_json::from_slice(&fs::read(&manifest_path).map_err(|error| format!("could not read final demo manifest: {error}"))?).map_err(|error| format!("final demo manifest is invalid: {error}"))?, "provider-a")?
                },
                {
                    "pubkey":b.provider_pubkey,
                    "quote_id":b.quote_id,
                    "quote_lifetime_seconds":b.quote_lifetime_seconds,
                    "desired_completion_time":b.desired_completion_time,
                    "output_amount":b.output_amount,
                    "maximum_total_fee":b.maximum_total_fee,
                    "close_id":b.close_id,
                    "restart_count":0
                }
            ],
            "external_spend_effects":0
        })
    );
    Ok(())
}

fn demo_provider(manifest: &Value, role: &str) -> Result<(String, String), String> {
    let provider = manifest
        .get("providers")
        .and_then(Value::as_array)
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider.get("role").and_then(Value::as_str) == Some(role))
        })
        .ok_or_else(|| format!("demo manifest omits {role}"))?;
    let pubkey = provider
        .get("pubkey")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(is_lower_hex))
        .ok_or_else(|| format!("demo manifest has an invalid {role} public key"))?;
    let offering = provider
        .get("offering_coordinate")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with(&format!("39601:{pubkey}:")))
        .ok_or_else(|| format!("demo manifest has an invalid {role} Offering"))?;
    Ok((pubkey.to_owned(), offering.to_owned()))
}

fn demo_restart_count(manifest: &Value, role: &str) -> Result<u64, String> {
    demo_provider_value(manifest, role, "/health/restart_count")?
        .as_u64()
        .ok_or_else(|| format!("demo manifest has an invalid {role} restart count"))
}

fn demo_health_state<'a>(manifest: &'a Value, role: &str) -> Result<&'a str, String> {
    demo_provider_value(manifest, role, "/health/state")?
        .as_str()
        .ok_or_else(|| format!("demo manifest has an invalid {role} health state"))
}

fn demo_provider_value<'a>(
    manifest: &'a Value,
    role: &str,
    pointer: &str,
) -> Result<&'a Value, String> {
    manifest
        .get("providers")
        .and_then(Value::as_array)
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider.get("role").and_then(Value::as_str) == Some(role))
        })
        .and_then(|provider| provider.pointer(pointer))
        .ok_or_else(|| format!("demo manifest omits {role}{pointer}"))
}

fn verify_demo_discovery(relay_url: &str, providers: &[&(String, String)]) -> Result<(), String> {
    let mut relay = connect(relay_url)?;
    send_json(
        &mut relay.websocket,
        json!(["REQ", "demo-discovery", {"kinds":[MKT_PROVIDER_PROFILE_KIND,MKT_OFFERING_KIND],"limit":16}]),
    )?;
    let mut events = Vec::new();
    loop {
        let message = read_json(&mut relay.websocket)?;
        if message == json!(["EOSE", "demo-discovery"]) {
            break;
        }
        if let Some(value) = message
            .as_array()
            .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
            .and_then(|fields| fields.get(2))
        {
            events.push(
                serde_json::from_value::<Event>(value.clone())
                    .map_err(|error| format!("demo discovery returned a non-event: {error}"))?,
            );
        }
    }
    for (pubkey, offering) in providers {
        let distinct = offering
            .rsplit_once(':')
            .map(|(_, distinct)| distinct)
            .ok_or_else(|| "demo Offering coordinate is invalid".to_owned())?;
        if !events
            .iter()
            .any(|event| event.kind == MKT_PROVIDER_PROFILE_KIND && event.pubkey == *pubkey)
            || !events.iter().any(|event| {
                event.kind == MKT_OFFERING_KIND
                    && event.pubkey == *pubkey
                    && tag_value(event, "d") == Some(distinct)
            })
        {
            return Err(format!("relay discovery omits signed heads for {pubkey}"));
        }
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn publish_incompatible_rfq(relay_url: &str, provider_pubkey: &str) -> Result<(), String> {
    let requester = MarketSigner::from_secret_bytes([9; 32])?;
    let session_id = digest("live-no-spend-incompatible-session");
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config)
        .map_err(|error| format!("could not initialize incompatible RFQ factory: {error}"))?;
    let mut profile = fixture_profile("submarine", 39_604, None)?;
    profile["constraints"]["maximum_total_fee"] = Value::String("1".to_owned());
    let now = unix_now()?;
    let rfq = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("incompatible-rfq:{session_id}")),
                now.saturating_add(300),
                profile,
            )
            .map_err(|error| format!("could not construct incompatible valid RFQ: {error}"))?,
        &requester,
    )?;
    let mut publisher = connect(relay_url)?;
    publish_private(&mut publisher, &rfq, &requester, provider_pubkey)
}

fn drive_flow(
    relay_url: &str,
    provider_pubkey: &str,
    requester_secret_byte: u8,
    swap_type: &str,
    restart_after_order: bool,
    provider: &mut ProviderProcess,
) -> Result<(), String> {
    let offering = format!("39601:{provider_pubkey}:{OFFERING_ID}");
    let session_label = format!("live-no-spend-{swap_type}");
    if restart_after_order {
        let mut restart = || {
            provider.stop()?;
            *provider = ProviderProcess::start(relay_url)?;
            Ok(())
        };
        drive_flow_with_restart(
            relay_url,
            provider_pubkey,
            &offering,
            requester_secret_byte,
            swap_type,
            &session_label,
            Some(&mut restart),
        )?;
    } else {
        drive_flow_with_restart(
            relay_url,
            provider_pubkey,
            &offering,
            requester_secret_byte,
            swap_type,
            &session_label,
            None,
        )?;
    }
    Ok(())
}

fn drive_flow_with_restart(
    relay_url: &str,
    provider_pubkey: &str,
    offering_address: &str,
    requester_secret_byte: u8,
    swap_type: &str,
    session_label: &str,
    mut restart_after_order: Option<&mut dyn FnMut() -> Result<(), String>>,
) -> Result<FlowReceipt, String> {
    let requester = MarketSigner::from_secret_bytes([requester_secret_byte; 32])?;
    let session_id = digest(&format!(
        "live-no-spend-session:{session_label}:{swap_type}"
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: offering_address.to_owned(),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config.clone())
        .map_err(|error| format!("could not initialize requester factory: {error}"))?;
    let mut verifier = ProviderSession::new(config.clone())
        .map_err(|error| format!("could not initialize live verifier: {error}"))?;
    let now = unix_now()?;

    let mut reader = connect(relay_url)?;
    authenticate(&mut reader, &requester, relay_url, now)?;
    subscribe(&mut reader, requester.pubkey())?;
    drain_history(&mut reader)?;
    let mut publisher = connect(relay_url)?;

    let rfq = sign_request(
        browser_signing_request(
            "requester_rfq",
            json!({
                "config": config,
                "created_at": now,
                "distinct": digest(&format!("rfq:{session_id}")),
                "expiration": now.saturating_add(900),
                "mkt_swp": fixture_profile(swap_type, 39_604, None)?
            }),
        )?,
        &requester,
    )?;
    verifier
        .ingest_signed(rfq.clone())
        .map_err(|error| format!("live verifier rejected RFQ: {error}"))?;
    publish_private(&mut publisher, &rfq, &requester, provider_pubkey)?;

    let quote = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_QUOTE_KIND
    })?;
    verifier
        .ingest_signed(quote.clone())
        .map_err(|error| format!("live verifier rejected Quote: {error}"))?;
    let quote_expiration = tag_value(&quote, "expiration")
        .ok_or_else(|| "live Quote omitted expiration".to_owned())?
        .parse::<u64>()
        .map_err(|_| "live Quote expiration is invalid".to_owned())?;
    let quote_profile = record_profile(&quote)?;
    let quote_terms = quote_profile
        .get("terms")
        .and_then(Value::as_object)
        .ok_or_else(|| "live Quote omitted terms".to_owned())?;
    let quote_lifetime_seconds = quote_expiration.saturating_sub(quote.created_at);
    let desired_completion_time = quote_terms
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| "live Quote omitted desired completion time".to_owned())?;
    let output_amount = quote_terms
        .get("output_amount")
        .and_then(Value::as_str)
        .ok_or_else(|| "live Quote omitted output amount".to_owned())?
        .to_owned();
    let maximum_total_fee = quote_terms
        .get("maximum_total_fee")
        .and_then(Value::as_str)
        .ok_or_else(|| "live Quote omitted maximum total fee".to_owned())?
        .to_owned();
    let quote_id = quote.id.clone();
    let order = sign_request(
        browser_signing_request(
            "requester_order",
            json!({
                "config": config,
                "rfq": rfq,
                "quote": quote,
                "created_at": quote.created_at.saturating_add(1),
                "observed_at": quote.created_at,
                "distinct": digest(&format!("order:{session_id}")),
                "selection": null
            }),
        )?,
        &requester,
    )?;
    verifier
        .ingest_signed(order.clone())
        .map_err(|error| format!("live verifier rejected Order: {error}"))?;
    publish_private(&mut publisher, &order, &requester, provider_pubkey)?;

    if let Some(restart) = restart_after_order.as_mut() {
        restart()?;
    }

    let requester_status = sign_request(
        factory
            .status(
                ParticipantRole::Requester,
                order.created_at.saturating_add(1),
                &digest(&format!("requester-status:{session_id}")),
                &order.id,
                immortal_client::mkt_swp_client::StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Map::new(),
            )
            .map_err(|error| format!("could not construct requester Status: {error}"))?,
        &requester,
    )?;
    verifier
        .ingest_signed(requester_status.clone())
        .map_err(|error| format!("live verifier rejected requester Status: {error}"))?;
    publish_private(
        &mut publisher,
        &requester_status,
        &requester,
        provider_pubkey,
    )?;

    let contract = complete_contract(swap_type, &config, &rfq, &quote, &order)?;
    let requester_contract = sign_request(
        browser_signing_request(
            "requester_contract",
            json!({
                "config": config,
                "rfq": rfq,
                "quote": quote,
                "order": order,
                "order_observed_at": order.created_at,
                "created_at": requester_status.created_at.saturating_add(1),
                "distinct": digest(&format!("requester-contract:{session_id}")),
                "contract": contract
            }),
        )?,
        &requester,
    )?;
    verifier
        .ingest_signed(requester_contract.clone())
        .map_err(|error| format!("live verifier rejected requester contract: {error}"))?;
    publish_private(
        &mut publisher,
        &requester_contract,
        &requester,
        provider_pubkey,
    )?;

    let provider_contract = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == provider_pubkey
    })?;
    if record_profile(&provider_contract)?.get("contract") != Some(&contract) {
        return Err("provider countersigned different contract terms".to_owned());
    }
    verifier
        .ingest_signed(provider_contract.clone())
        .map_err(|error| format!("live verifier rejected provider contract: {error}"))?;
    let status = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_STATUS_KIND
    })?;
    verifier
        .ingest_signed(status.clone())
        .map_err(|error| format!("live verifier rejected Status: {error}"))?;

    let cancel_request = sign_request(
        browser_signing_request(
            "requester_cancel",
            json!({
                "config": config,
                "created_at": status.created_at.saturating_add(1),
                "distinct": digest(&format!("cancel-request:{session_id}")),
                "order_id": order.id,
                "cancellation": {
                    "action": "request",
                    "reason": "live_no_spend_smoke",
                    "request_id": null,
                    "accepted_id": null
                },
                "mkt_swp": {"disposition":"no_funding_authorized"}
            }),
        )?,
        &requester,
    )?;
    verifier
        .ingest_signed(cancel_request.clone())
        .map_err(|error| format!("live verifier rejected Cancel request: {error}"))?;
    publish_private(&mut publisher, &cancel_request, &requester, provider_pubkey)?;

    let accepted = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_CANCEL_KIND && tag_value(event, "action") == Some("accepted")
    })?;
    verifier
        .ingest_signed(accepted.clone())
        .map_err(|error| format!("live verifier rejected accepted Cancel: {error}"))?;
    let effective = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_CANCEL_KIND && tag_value(event, "action") == Some("effective")
    })?;
    verifier
        .ingest_signed(effective.clone())
        .map_err(|error| format!("live verifier rejected effective Cancel: {error}"))?;
    let close = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_CLOSE_KIND
    })?;
    let close_profile = record_profile(&close)?;
    if close_profile
        .get("external_spend_effects")
        .and_then(Value::as_u64)
        != Some(0)
        || close_profile
            .get("loss_accounting")
            .and_then(|loss| loss.get("input_committed"))
            .and_then(Value::as_str)
            != Some("0")
    {
        return Err("provider Close is not exact no-spend accounting".to_owned());
    }
    verifier
        .ingest_signed(close.clone())
        .map_err(|error| format!("live verifier rejected Close: {error}"))?;
    let snapshot = verifier
        .persist()
        .map_err(|error| format!("could not persist live verifier: {error}"))?;
    ProviderSession::restore(&snapshot)
        .map_err(|error| format!("could not restore completed live session: {error}"))?;

    let records = vec![
        rfq,
        quote,
        order,
        requester_status,
        requester_contract,
        provider_contract,
        status,
        cancel_request,
        accepted,
        effective,
        close.clone(),
    ];
    let deliveries = browser_deliveries(&records)?;
    let created = browser_invoke(
        "session_create",
        json!({
            "config": config,
            "records": records,
            "exit_packages": [],
            "deliveries": deliveries
        }),
    )?;
    let created_snapshot = created
        .get("snapshot_json_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "browser session create omitted snapshot".to_owned())?;
    let restored = browser_invoke(
        "session_restore",
        json!({
            "snapshot_json_hex": created_snapshot,
            "deliveries": deliveries
        }),
    )?;
    if created.get("view") != restored.get("view")
        || restored.get("snapshot_json_hex").and_then(Value::as_str) != Some(created_snapshot)
    {
        return Err("browser persist/reload changed the no-spend requester session".to_owned());
    }
    let replay = browser_invoke(
        "session_ingest",
        json!({
            "snapshot_json_hex": created_snapshot,
            "records": [close],
            "deliveries": deliveries
        }),
    )?;
    if replay.get("ingested_records").and_then(Value::as_u64) != Some(0)
        || replay.get("snapshot_json_hex").and_then(Value::as_str) != Some(created_snapshot)
    {
        return Err("browser session replay duplicated a signed record or request".to_owned());
    }
    Ok(FlowReceipt {
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        quote_id,
        quote_lifetime_seconds,
        desired_completion_time,
        output_amount,
        maximum_total_fee,
        close_id: close.id,
    })
}

fn browser_signing_request(operation: &str, input: Value) -> Result<MktSigningRequest, String> {
    serde_json::from_value(browser_invoke(operation, input)?)
        .map_err(|error| format!("browser {operation} output is not a signing request: {error}"))
}

fn browser_invoke(operation: &str, input: Value) -> Result<Value, String> {
    let request = serde_json::to_vec(&json!({
        "abi_version": 1,
        "operation": operation,
        "input": input
    }))
    .map_err(|error| format!("could not encode browser {operation} request: {error}"))?;
    if immortal_client_web::immortal_mkt_swp_browser_request_reset() != 0 {
        return Err(format!("browser {operation} request reset failed"));
    }
    for byte in request {
        if immortal_client_web::immortal_mkt_swp_browser_request_push(u32::from(byte)) != 0 {
            return Err(format!("browser {operation} request transfer failed"));
        }
    }
    if immortal_client_web::immortal_mkt_swp_browser_invoke() != 0 {
        return Err(format!("browser {operation} invocation failed"));
    }
    let response_bytes = (0..immortal_client_web::immortal_mkt_swp_browser_response_len())
        .map(|index| immortal_client_web::immortal_mkt_swp_browser_response_byte(index))
        .map(|byte| {
            u8::try_from(byte)
                .map_err(|_| format!("browser {operation} response transfer ended early"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let response: Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| format!("browser {operation} response is invalid JSON: {error}"))?;
    if let Some(error) = response.get("error") {
        return Err(format!("browser {operation} failed: {error}"));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| format!("browser {operation} response omitted result"))
}

fn browser_deliveries(records: &[Event]) -> Result<Vec<Value>, String> {
    records
        .iter()
        .map(|record| {
            let raw = serde_json::to_vec(record)
                .map_err(|error| format!("could not encode browser delivery: {error}"))?;
            Ok(json!({
                "raw_signed_event_hex": lower_hex(&raw),
                "observed_at": record.created_at,
                "provenance": "direct"
            }))
        })
        .collect()
}

fn fixture_profile(swap_type: &str, kind: u64, signer_role: Option<&str>) -> Result<Value, String> {
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
        .find(|record| {
            record.get("kind").and_then(Value::as_u64) == Some(kind)
                && signer_role.is_none_or(|role| {
                    record
                        .get("content")
                        .and_then(Value::as_str)
                        .and_then(|content| serde_json::from_str::<Value>(content).ok())
                        .and_then(|content| {
                            content
                                .get("mkt_swp")
                                .and_then(|profile| profile.get("signer_role"))
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .as_deref()
                        == Some(role)
                })
        })
        .and_then(|record| record.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("full-session fixture has no kind {kind} record"))?;
    serde_json::from_str::<Value>(content)
        .map_err(|error| format!("fixture record is invalid JSON: {error}"))?
        .get("mkt_swp")
        .cloned()
        .ok_or_else(|| "fixture record has no MKT-SWP profile".to_owned())
}

fn complete_contract(
    swap_type: &str,
    config: &SwapClientConfig,
    rfq: &Event,
    quote: &Event,
    order: &Event,
) -> Result<Value, String> {
    let mut contract = fixture_profile(swap_type, 39_610, Some("requester"))?
        .get("contract")
        .cloned()
        .ok_or_else(|| "fixture requester contract has no contract".to_owned())?;
    let quote_profile = record_profile(quote)?;
    let terms = quote_profile
        .get("terms")
        .and_then(Value::as_object)
        .ok_or_else(|| "live Quote has no terms".to_owned())?;
    for member in [
        "swap_type",
        "asset_pair",
        "payment_hash",
        "fee_bps",
        "provider_fee",
        "miner_fee_budget",
        "lightning_routing_fee_budget",
        "maximum_total_fee",
        "amount_equation",
        "rounding",
        "script_mode",
        "desired_completion_time",
        "clock_skew_seconds",
        "legs",
        "timeout_ladder",
        "verifier_inputs",
        "cancellation",
        "evidence_requirements",
        "recovery",
        "price_feed",
        "evm_leg",
        "input_amount",
        "output_amount",
        "fee_payer",
        "confirmation_policy",
    ] {
        contract[member] = terms
            .get(member)
            .cloned()
            .ok_or_else(|| format!("live Quote terms omit {member}"))?;
    }
    contract["order_id"] = Value::String(order.id.clone());
    contract["quote_id"] = Value::String(quote.id.clone());
    let reservation = quote_profile
        .get("reservation_terms")
        .and_then(Value::as_object)
        .ok_or_else(|| "live Quote has no reservation terms".to_owned())?;
    let proof_ref = reservation
        .get("proof_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "live Quote reservation has no proof reference".to_owned())?;
    contract["reservation_commitment"] = json!({
        "session_id":config.session_id,
        "rfq_id":rfq.id,
        "quote_id":quote.id,
        "reservation_id":reservation["reservation_id"],
        "reservation_class":"soft",
        "capacity_bucket_id":reservation["capacity_bucket_id"],
        "reserved_asset_id":reservation["reserved_asset_id"],
        "reserved_amount":reservation["reserved_amount"],
        "handler_committed_capacity":reservation["handler_committed_capacity"],
        "allocation_sequence":reservation["allocation_sequence"],
        "proof_class":reservation["proof_class"],
        "proof_strength":10,
        "proof_ref_sha256":lower_hex(&Sha256::digest(proof_ref.as_bytes())),
        "capacity_commitment_sha256":reservation["capacity_commitment_sha256"],
        "reservation_expires_at":reservation["reservation_expires_at"],
        "profile_timeout_at":null,
        "covenant_commitment":null
    });
    Ok(contract)
}

fn sign_request(
    request: immortal_client::mkt_swp_client::MktSigningRequest,
    signer: &MarketSigner,
) -> Result<Event, String> {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request
        .verify_signed(event)
        .map_err(|error| format!("request signature failed: {error}"))
}

fn publish_private(
    publisher: &mut RelayClient,
    event: &Event,
    sender: &MarketSigner,
    recipient: &str,
) -> Result<(), String> {
    let raw = serde_json::to_vec(event)
        .map_err(|error| format!("could not serialize private event: {error}"))?;
    let wrap = wrap_mkt_record(&raw, sender, recipient, random_wrap_material()?)?;
    publish(publisher, &wrap.event)
}

fn receive_matching<F>(
    reader: &mut RelayClient,
    recipient: &MarketSigner,
    session_id: &str,
    matches: F,
) -> Result<Event, String>
where
    F: Fn(&Event) -> bool,
{
    for _ in 0..128 {
        let message = read_json(&mut reader.websocket)?;
        let Some(value) = message
            .as_array()
            .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
            .and_then(|fields| fields.get(2))
        else {
            continue;
        };
        let wrap: Event = serde_json::from_value(value.clone())
            .map_err(|error| format!("live subscription payload is not an event: {error}"))?;
        let delivered = unwrap_mkt_record(&wrap, recipient, &swp_profiles())?;
        if delivered.record().envelope().session_id == session_id
            && matches(delivered.record().event())
        {
            return Ok(delivered.record().event().clone());
        }
    }
    Err(format!(
        "no matching provider record arrived for session {session_id}"
    ))
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
                let (mut websocket, _) = client(relay_url, stream)
                    .map_err(|error| format!("could not open relay WebSocket: {error}"))?;
                let challenge_message = read_json(&mut websocket)?;
                let challenge = challenge_message
                    .as_array()
                    .filter(|fields| fields.first().and_then(Value::as_str) == Some("AUTH"))
                    .and_then(|fields| fields.get(1))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "relay did not send NIP-42 challenge".to_owned())?
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
        "could not connect to relay: {}",
        last_error.map_or_else(|| "no address".to_owned(), |error| error.to_string())
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
            Tag::new(vec!["relay".into(), relay_url.into()]),
            Tag::new(vec!["challenge".into(), client.challenge.clone()]),
        ],
        String::new(),
    );
    send_json(&mut client.websocket, json!(["AUTH", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn subscribe(client: &mut RelayClient, recipient: &str) -> Result<(), String> {
    send_json(
        &mut client.websocket,
        json!(["REQ", "live-requester", {"kinds":[1059],"#p":[recipient],"limit":512}]),
    )
}

fn drain_history(client: &mut RelayClient) -> Result<(), String> {
    loop {
        let message = read_json(&mut client.websocket)?;
        if message == json!(["EOSE", "live-requester"]) {
            return Ok(());
        }
    }
}

fn publish(client: &mut RelayClient, event: &Event) -> Result<(), String> {
    send_json(&mut client.websocket, json!(["EVENT", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn expect_ok(websocket: &mut RelaySocket, event_id: &str) -> Result<(), String> {
    let response = read_json(websocket)?;
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
    websocket
        .send(Message::text(value.to_string()))
        .map_err(|error| format!("could not write relay message: {error}"))
}

fn read_json(websocket: &mut RelaySocket) -> Result<Value, String> {
    loop {
        match websocket.read() {
            Ok(Message::Text(text)) => {
                return serde_json::from_str(text.as_str())
                    .map_err(|error| format!("relay message is invalid JSON: {error}"));
            }
            Ok(Message::Ping(payload)) => websocket
                .send(Message::Pong(payload))
                .map_err(|error| format!("could not answer relay ping: {error}"))?,
            Ok(Message::Pong(_)) => {}
            Ok(message) => return Err(format!("unexpected relay frame: {message:?}")),
            Err(error) => return Err(format!("could not read relay message: {error}")),
        }
    }
}

fn loopback_addresses(relay_url: &str) -> Result<Vec<SocketAddr>, String> {
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| "live smoke accepts only ws:// relay URLs".to_owned())?
        .split('/')
        .next()
        .unwrap_or_default();
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("live smoke refuses non-loopback relay addresses".to_owned());
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn swp_profiles() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }]
}

fn record_profile(event: &Event) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Value>(&event.content)
        .map_err(|error| format!("record content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "record has no MKT-SWP profile".to_owned())
}

fn tag_value<'a>(event: &'a Event, name: &'a str) -> Option<&'a str> {
    event.tag_values(name).next()
}

fn random_wrap_material() -> Result<WrapMaterial, String> {
    let now = unix_now()?;
    Ok(WrapMaterial {
        seal_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        wrap_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        rumor_identifier: random_32()?,
        seal_nonce: random_32()?,
        wrap_nonce: random_32()?,
        wrap_secret: random_secret()?,
    })
}

fn random_secret() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate one-time wrapping key".to_owned())
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

fn digest(value: &str) -> String {
    lower_hex(&Sha256::digest(value.as_bytes()))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))
}

fn stop_child(child: &mut Child) {
    if let Err(error) = child.kill() {
        eprintln!("could not stop failed provider process: {error}");
    }
    if let Err(error) = child.wait() {
        eprintln!("could not reap failed provider process: {error}");
    }
}
