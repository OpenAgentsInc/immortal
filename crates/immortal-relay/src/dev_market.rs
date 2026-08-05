//! Local-only two-party NIP-MKT smoke driver.

use std::{
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message, WebSocket, client};

use crate::{
    domain::{
        Event, MKT_CLOSE_KIND, MKT_ENVELOPE_SCHEMA, MKT_OFFERING_KIND, MKT_ORDER_KIND,
        MKT_PROVIDER_PROFILE_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND,
        MktProfileSupport, Tag, validate_mkt_private_raw, validate_mkt_public_event,
    },
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record, wrap_mkt_record},
};

const PROFILE_ID: &str = "local-dev";
const PROFILE_VERSION: u64 = 1;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize)]
pub struct DevMarketTrace {
    pub contract_version: u64,
    pub relay_url: String,
    pub requester_pubkey: String,
    pub provider_pubkey: String,
    pub provider_profile_id: String,
    pub offering_id: String,
    pub session_id: String,
    pub steps: Vec<DevMarketStep>,
    pub final_state: String,
    pub settlement_claim: String,
}

#[derive(Debug, Serialize)]
pub struct DevMarketStep {
    pub name: &'static str,
    pub kind: u16,
    pub inner_event_id: String,
    pub counterparty_wrap_id: String,
    pub recovery_wrap_id: String,
}

pub(crate) struct RelayClient {
    pub(crate) websocket: WebSocket<TcpStream>,
    pub(crate) challenge: String,
}

pub fn seed(relay_url: &str) -> Result<DevMarketTrace, String> {
    let now = unix_now()?;
    let requester = random_signer()?;
    let provider = random_signer()?;
    let session_id = random_hex_32()?;
    let provider_id = "local-provider";
    let offering_distinct = "local-offering";

    let mut requester_reader = connect(relay_url)?;
    authenticate(&mut requester_reader, &requester, relay_url, now)?;
    subscribe(&mut requester_reader, "requester-mkt", requester.pubkey())?;
    let mut provider_reader = connect(relay_url)?;
    authenticate(&mut provider_reader, &provider, relay_url, now)?;
    subscribe(&mut provider_reader, "provider-mkt", provider.pubkey())?;
    let mut requester_publisher = connect(relay_url)?;
    let mut provider_publisher = connect(relay_url)?;

    let provider_profile = provider.sign(
        now,
        MKT_PROVIDER_PROFILE_KIND,
        vec![
            tag(&["d", provider_id]),
            tag(&["status", "active"]),
            tag(&["published_at", &now.to_string()]),
            tag(&["profile", PROFILE_ID, "1"]),
        ],
        json!({"name":"Local demo provider"}).to_string(),
    );
    validate_mkt_public_event(&provider_profile)?;
    publish(&mut provider_publisher, &provider_profile)?;

    let provider_address = format!("39600:{}:{provider_id}", provider.pubkey());
    let offering_address = format!("39601:{}:{offering_distinct}", provider.pubkey());
    let offering = provider.sign(
        now,
        MKT_OFFERING_KIND,
        vec![
            tag(&["d", offering_distinct]),
            tag(&["status", "active"]),
            tag(&["published_at", &now.to_string()]),
            tag(&["profile", PROFILE_ID, "1"]),
            tag(&["provider", &provider_address]),
        ],
        json!({"name":"Local smoke service","unit":"session"}).to_string(),
    );
    validate_mkt_public_event(&offering)?;
    publish(&mut provider_publisher, &offering)?;

    let profiles = [MktProfileSupport {
        profile_id: PROFILE_ID,
        version: PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }];
    let mut steps = Vec::new();
    let rfq = private_record(
        &requester,
        &provider,
        "provider",
        MKT_RFQ_KIND,
        now,
        &session_id,
        "RFQ",
        vec![Tag::new(vec![
            "a".into(),
            offering_address,
            String::new(),
            "offering".into(),
        ])],
        json!({"request":"one local smoke session"}),
        &profiles,
    )?;
    exchange(
        "rfq",
        &rfq,
        &requester,
        &provider,
        &mut requester_publisher,
        &mut requester_reader,
        &mut provider_reader,
        &profiles,
        &mut steps,
    )?;

    let quote = private_record(
        &provider,
        &requester,
        "requester",
        MKT_QUOTE_KIND,
        now + 1,
        &session_id,
        "Quote",
        vec![reference(&rfq.id, "rfq")],
        json!({"quote_class":"firm","reservation":"hard","amount":"1","currency":"DEV"}),
        &profiles,
    )?;
    exchange(
        "quote",
        &quote,
        &provider,
        &requester,
        &mut provider_publisher,
        &mut provider_reader,
        &mut requester_reader,
        &profiles,
        &mut steps,
    )?;

    let order = private_record(
        &requester,
        &provider,
        "provider",
        MKT_ORDER_KIND,
        now + 2,
        &session_id,
        "Order",
        vec![reference(&quote.id, "quote")],
        json!({"accept_quote":quote.id}),
        &profiles,
    )?;
    exchange(
        "order",
        &order,
        &requester,
        &provider,
        &mut requester_publisher,
        &mut requester_reader,
        &mut provider_reader,
        &profiles,
        &mut steps,
    )?;

    let status = private_record(
        &provider,
        &requester,
        "requester",
        MKT_STATUS_KIND,
        now + 3,
        &session_id,
        "Status",
        vec![reference(&order.id, "order")],
        json!({"seq":0,"state":"completed"}),
        &profiles,
    )?;
    exchange(
        "status",
        &status,
        &provider,
        &requester,
        &mut provider_publisher,
        &mut provider_reader,
        &mut requester_reader,
        &profiles,
        &mut steps,
    )?;

    let close = private_record(
        &requester,
        &provider,
        "provider",
        MKT_CLOSE_KIND,
        now + 4,
        &session_id,
        "Close",
        vec![
            reference(&order.id, "order"),
            reference(&status.id, "status"),
        ],
        json!({"outcome":"completed","terminal_at":now + 4,"settlement":"coordination_only"}),
        &profiles,
    )?;
    exchange(
        "close",
        &close,
        &requester,
        &provider,
        &mut requester_publisher,
        &mut requester_reader,
        &mut provider_reader,
        &profiles,
        &mut steps,
    )?;

    close_socket(&mut requester_reader.websocket);
    close_socket(&mut provider_reader.websocket);
    close_socket(&mut requester_publisher.websocket);
    close_socket(&mut provider_publisher.websocket);
    Ok(DevMarketTrace {
        contract_version: 1,
        relay_url: relay_url.to_owned(),
        requester_pubkey: requester.pubkey().to_owned(),
        provider_pubkey: provider.pubkey().to_owned(),
        provider_profile_id: provider_profile.id,
        offering_id: offering.id,
        session_id,
        steps,
        final_state: "completed".to_owned(),
        settlement_claim:
            "coordination_only; relay acceptance proves transport, not payment or execution"
                .to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
fn exchange(
    name: &'static str,
    event: &Event,
    sender: &MarketSigner,
    counterparty: &MarketSigner,
    publisher: &mut RelayClient,
    sender_reader: &mut RelayClient,
    counterparty_reader: &mut RelayClient,
    profiles: &[MktProfileSupport<'_>],
    steps: &mut Vec<DevMarketStep>,
) -> Result<(), String> {
    let raw = serde_json::to_vec(event)
        .map_err(|error| format!("could not serialize {name}: {error}"))?;
    let counterparty_wrap =
        wrap_mkt_record(&raw, sender, counterparty.pubkey(), random_wrap_material()?)?;
    let recovery_wrap = wrap_mkt_record(&raw, sender, sender.pubkey(), random_wrap_material()?)?;
    publish(publisher, &counterparty_wrap.event)?;
    publish(publisher, &recovery_wrap.event)?;
    receive_exact(
        counterparty_reader,
        counterparty,
        &counterparty_wrap.event.id,
        &event.id,
        profiles,
    )?;
    receive_exact(
        sender_reader,
        sender,
        &recovery_wrap.event.id,
        &event.id,
        profiles,
    )?;
    steps.push(DevMarketStep {
        name,
        kind: event.kind,
        inner_event_id: event.id.clone(),
        counterparty_wrap_id: counterparty_wrap.event.id,
        recovery_wrap_id: recovery_wrap.event.id,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn private_record(
    author: &MarketSigner,
    counterparty: &MarketSigner,
    role: &str,
    kind: u16,
    created_at: u64,
    session_id: &str,
    label: &str,
    mut references: Vec<Tag>,
    fields: Value,
    profiles: &[MktProfileSupport<'_>],
) -> Result<Event, String> {
    let mut tags = vec![
        tag(&["d", &random_hex_32()?]),
        tag(&["session", session_id]),
        tag(&["profile", PROFILE_ID, "1"]),
        Tag::new(vec![
            "p".into(),
            counterparty.pubkey().into(),
            String::new(),
            role.to_owned(),
        ]),
        tag(&["alt", &format!("Local development {label}")]),
    ];
    tags.append(&mut references);
    let mut body = fields
        .as_object()
        .cloned()
        .ok_or_else(|| "private MKT smoke fields must be an object".to_owned())?;
    body.insert("schema".into(), Value::String(MKT_ENVELOPE_SCHEMA.into()));
    body.insert("profile".into(), Value::String(PROFILE_ID.into()));
    body.insert("profile_version".into(), Value::from(PROFILE_VERSION));
    body.insert("session_id".into(), Value::String(session_id.into()));
    let event = author.sign(created_at, kind, tags, Value::Object(body).to_string());
    let raw = serde_json::to_vec(&event)
        .map_err(|error| format!("could not serialize {label}: {error}"))?;
    validate_mkt_private_raw(&raw, profiles)
        .map_err(|error| format!("local {label} is invalid: {error}"))?;
    Ok(event)
}

pub(crate) fn connect(relay_url: &str) -> Result<RelayClient, String> {
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
                    .filter(|message| message.first() == Some(&Value::String("AUTH".into())))
                    .and_then(|message| message.get(1))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "relay did not send a NIP-42 challenge".to_owned())?
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
        "could not connect to local relay: {}",
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
            tag(&["relay", relay_url]),
            tag(&["challenge", &client.challenge]),
        ],
        String::new(),
    );
    send_json(&mut client.websocket, json!(["AUTH", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn subscribe(client: &mut RelayClient, subscription: &str, recipient: &str) -> Result<(), String> {
    send_json(
        &mut client.websocket,
        json!(["REQ", subscription, {"kinds":[1059],"#p":[recipient]}]),
    )?;
    loop {
        let message = read_json(&mut client.websocket)?;
        if message == json!(["EOSE", subscription]) {
            return Ok(());
        }
        if message.get(0) != Some(&Value::String("EVENT".into())) {
            return Err(format!("unexpected subscription response: {message}"));
        }
    }
}

pub(crate) fn publish(client: &mut RelayClient, event: &Event) -> Result<(), String> {
    send_json(&mut client.websocket, json!(["EVENT", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn expect_ok(websocket: &mut WebSocket<TcpStream>, event_id: &str) -> Result<(), String> {
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

fn receive_exact(
    client: &mut RelayClient,
    recipient: &MarketSigner,
    wrap_id: &str,
    inner_id: &str,
    profiles: &[MktProfileSupport<'_>],
) -> Result<(), String> {
    let message = read_json(&mut client.websocket)?;
    let event_value = message
        .get(2)
        .filter(|_| message.get(0).and_then(Value::as_str) == Some("EVENT"))
        .ok_or_else(|| format!("unexpected live delivery: {message}"))?;
    let event: Event = serde_json::from_value(event_value.clone())
        .map_err(|error| format!("live delivery is not an event: {error}"))?;
    if event.id != wrap_id {
        return Err(format!(
            "received wrap {} while waiting for {wrap_id}",
            event.id
        ));
    }
    let delivered = unwrap_mkt_record(&event, recipient, profiles)?;
    if delivered.record().event().id != inner_id {
        return Err("gift wrap delivered a different private MKT record".to_owned());
    }
    Ok(())
}

pub(crate) fn send_json(websocket: &mut WebSocket<TcpStream>, value: Value) -> Result<(), String> {
    websocket
        .send(Message::text(value.to_string()))
        .map_err(|error| format!("could not write relay message: {error}"))
}

pub(crate) fn read_json(websocket: &mut WebSocket<TcpStream>) -> Result<Value, String> {
    loop {
        match websocket.read() {
            Ok(Message::Text(text)) => {
                return serde_json::from_str(text.as_str())
                    .map_err(|error| format!("relay message is invalid JSON: {error}"));
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(message) => return Err(format!("unexpected relay frame: {message:?}")),
            Err(error) => return Err(format!("could not read relay message: {error}")),
        }
    }
}

pub(crate) fn close_socket(websocket: &mut WebSocket<TcpStream>) {
    if let Err(error) = websocket.close(None) {
        eprintln!("dev-market-seed: WebSocket close failed: {error}");
    }
}

fn loopback_addresses(relay_url: &str) -> Result<Vec<SocketAddr>, String> {
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| "dev-market-seed accepts only ws:// loopback URLs".to_owned())?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || relay_url.contains('?')
        || relay_url.contains('#')
    {
        return Err("dev-market-seed relay URL is invalid".to_owned());
    }
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve local relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("dev-market-seed refuses non-loopback relay addresses".to_owned());
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn random_signer() -> Result<MarketSigner, String> {
    for _ in 0..32 {
        if let Ok(signer) = MarketSigner::from_secret_bytes(random_32()?) {
            return Ok(signer);
        }
    }
    Err("could not generate a valid throwaway market key".to_owned())
}

fn random_wrap_material() -> Result<WrapMaterial, String> {
    let now = unix_now()?;
    let offset = u64::from(random_32()?[0]) * 10;
    let wrap_secret = random_secret_bytes()?;
    Ok(WrapMaterial {
        seal_created_at: now.saturating_sub(offset),
        wrap_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        seal_nonce: random_32()?,
        wrap_nonce: random_32()?,
        wrap_secret,
    })
}

fn random_secret_bytes() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate a valid throwaway wrapping key".to_owned())
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

pub(crate) fn random_hex_32() -> Result<String, String> {
    Ok(lower_hex(&random_32()?))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

fn reference(id: &str, marker: &str) -> Tag {
    Tag::new(vec!["e".into(), id.into(), String::new(), marker.into()])
}

pub(crate) fn tag(values: &[&str]) -> Tag {
    Tag::new(values.iter().map(|value| (*value).to_owned()).collect())
}
