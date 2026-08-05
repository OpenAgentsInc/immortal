use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{
    Cancellation, ParticipantRole, SwapClientConfig, SwapContractReferences, SwapRecordFactory,
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_QUOTE_KIND, MKT_STATUS_KIND,
        MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport,
        Tag,
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

fn publish_incompatible_rfq(relay_url: &str, provider_pubkey: &str) -> Result<(), String> {
    let requester = MarketSigner::from_secret_bytes([9; 32])?;
    let session_id = digest("live-no-spend-incompatible-session");
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
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
    let requester = MarketSigner::from_secret_bytes([requester_secret_byte; 32])?;
    let session_id = digest(&format!("live-no-spend-session:{swap_type}"));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
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
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(300),
                fixture_profile(swap_type, 39_604, None)?,
            )
            .map_err(|error| format!("could not construct live RFQ: {error}"))?,
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
    let order = sign_request(
        factory
            .order(
                quote.created_at.saturating_add(1),
                &digest(&format!("order:{session_id}")),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .map_err(|error| format!("could not construct live Order: {error}"))?,
        &requester,
    )?;
    verifier
        .ingest_signed(order.clone())
        .map_err(|error| format!("live verifier rejected Order: {error}"))?;
    publish_private(&mut publisher, &order, &requester, provider_pubkey)?;

    if restart_after_order {
        provider.stop()?;
        *provider = ProviderProcess::start(relay_url)?;
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
        factory
            .swap_contract(
                ParticipantRole::Requester,
                requester_status.created_at.saturating_add(1),
                &digest(&format!("requester-contract:{session_id}")),
                SwapContractReferences {
                    order_id: &order.id,
                    quote_id: &quote.id,
                    accepted_status_id: None,
                },
                contract.clone(),
            )
            .map_err(|error| format!("could not construct requester contract: {error}"))?,
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
        .ingest_signed(provider_contract)
        .map_err(|error| format!("live verifier rejected provider contract: {error}"))?;
    let status = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_STATUS_KIND
    })?;
    verifier
        .ingest_signed(status.clone())
        .map_err(|error| format!("live verifier rejected Status: {error}"))?;

    let cancel_request = sign_request(
        factory
            .cancel(
                ParticipantRole::Requester,
                status.created_at.saturating_add(1),
                &digest(&format!("cancel-request:{session_id}")),
                &order.id,
                Cancellation {
                    action: "request",
                    reason: "live_no_spend_smoke",
                    request_id: None,
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .map_err(|error| format!("could not construct Cancel request: {error}"))?,
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
        .ingest_signed(accepted)
        .map_err(|error| format!("live verifier rejected accepted Cancel: {error}"))?;
    let effective = receive_matching(&mut reader, &requester, &session_id, |event| {
        event.kind == MKT_CANCEL_KIND && tag_value(event, "action") == Some("effective")
    })?;
    verifier
        .ingest_signed(effective)
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
        .ingest_signed(close)
        .map_err(|error| format!("live verifier rejected Close: {error}"))?;
    let snapshot = verifier
        .persist()
        .map_err(|error| format!("could not persist live verifier: {error}"))?;
    ProviderSession::restore(&snapshot)
        .map_err(|error| format!("could not restore completed live session: {error}"))?;
    Ok(())
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
