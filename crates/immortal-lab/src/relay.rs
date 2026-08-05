//! Blocking loopback relay client for the lab harness.
//!
//! Mirrors the relay wire discipline used by the dev-market smoke and the
//! no-spend live test: plain `ws://` to a loopback address only, NIP-42
//! authentication for recipient-gated gift-wrap subscriptions, and OK-gated
//! publication.

use std::{
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use immortal_client::{
    domain::{Event, Tag},
    market::{MarketSigner, WrapMaterial, wrap_mkt_record},
};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message, WebSocket, client};

use crate::util::{random_32, random_secret, unix_now};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub type RelaySocket = WebSocket<TcpStream>;

pub struct RelayClient {
    websocket: RelaySocket,
    challenge: String,
}

/// The relay URL the lab targets: `IMMORTAL_LAB_RELAY_URL`, then
/// `IMMORTAL_DEV_RELAY_URL`, then the dev-relay default.
pub fn relay_url_from_env() -> String {
    std::env::var("IMMORTAL_LAB_RELAY_URL")
        .or_else(|_| std::env::var("IMMORTAL_DEV_RELAY_URL"))
        .unwrap_or_else(|_| "ws://127.0.0.1:18080".to_owned())
}

impl RelayClient {
    pub fn connect(relay_url: &str) -> Result<Self, String> {
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
                        .ok_or_else(|| "relay did not send a NIP-42 challenge".to_owned())?
                        .to_owned();
                    return Ok(Self {
                        websocket,
                        challenge,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(format!(
            "could not connect to lab relay: {}",
            last_error.map_or_else(|| "no address".to_owned(), |error| error.to_string())
        ))
    }

    pub fn authenticate(&mut self, signer: &MarketSigner, relay_url: &str) -> Result<(), String> {
        let event = signer.sign(
            unix_now()?,
            22_242,
            vec![
                Tag::new(vec!["relay".into(), relay_url.into()]),
                Tag::new(vec!["challenge".into(), self.challenge.clone()]),
            ],
            String::new(),
        );
        send_json(&mut self.websocket, json!(["AUTH", event]))?;
        expect_ok(&mut self.websocket, &event.id)
    }

    /// Open a subscription and return every stored event up to EOSE.
    pub fn request_stored(
        &mut self,
        subscription: &str,
        filter: Value,
    ) -> Result<Vec<Event>, String> {
        send_json(&mut self.websocket, json!(["REQ", subscription, filter]))?;
        let mut events = Vec::new();
        loop {
            let message = read_json(&mut self.websocket)?;
            if message == json!(["EOSE", subscription]) {
                return Ok(events);
            }
            let Some(value) = message
                .as_array()
                .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
                .and_then(|fields| fields.get(2))
            else {
                continue;
            };
            let event: Event = serde_json::from_value(value.clone())
                .map_err(|error| format!("relay delivered a non-event payload: {error}"))?;
            events.push(event);
        }
    }

    /// Read one live event from an already-open subscription. `Ok(None)`
    /// means the wait window elapsed without a delivery.
    pub fn next_live_event(&mut self) -> Result<Option<Event>, String> {
        loop {
            match self.websocket.read() {
                Ok(Message::Text(text)) => {
                    let message: Value = serde_json::from_str(text.as_str())
                        .map_err(|error| format!("relay message is invalid JSON: {error}"))?;
                    let Some(value) = message
                        .as_array()
                        .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
                        .and_then(|fields| fields.get(2))
                    else {
                        continue;
                    };
                    let event: Event = serde_json::from_value(value.clone())
                        .map_err(|error| format!("relay delivered a non-event payload: {error}"))?;
                    return Ok(Some(event));
                }
                Ok(Message::Ping(payload)) => self
                    .websocket
                    .send(Message::Pong(payload))
                    .map_err(|error| format!("could not answer relay ping: {error}"))?,
                Ok(Message::Pong(_)) => {}
                Ok(message) => return Err(format!("unexpected relay frame: {message:?}")),
                Err(tokio_tungstenite::tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(format!("could not read relay message: {error}")),
            }
        }
    }

    pub fn publish(&mut self, event: &Event) -> Result<(), String> {
        send_json(&mut self.websocket, json!(["EVENT", event]))?;
        expect_ok(&mut self.websocket, &event.id)
    }

    /// Gift-wrap a signed private MKT record for `recipient` and publish it.
    /// Returns the wrap event id.
    pub fn publish_wrapped(
        &mut self,
        event: &Event,
        sender: &MarketSigner,
        recipient: &str,
    ) -> Result<String, String> {
        let raw = serde_json::to_vec(event)
            .map_err(|error| format!("could not serialize private record: {error}"))?;
        let wrap = wrap_mkt_record(&raw, sender, recipient, random_wrap_material()?)?;
        self.publish(&wrap.event)?;
        Ok(wrap.event.id)
    }

    pub fn close(&mut self) {
        if let Err(error) = self.websocket.close(None) {
            eprintln!("immortal-lab: WebSocket close failed: {error}");
        }
    }
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

/// The lab refuses non-loopback and non-`ws://` targets so throwaway
/// regtest traffic can never reach a production relay by mistake.
pub fn loopback_addresses(relay_url: &str) -> Result<Vec<SocketAddr>, String> {
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| "immortal-lab accepts only ws:// loopback URLs".to_owned())?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || relay_url.contains('?')
        || relay_url.contains('#')
    {
        return Err("immortal-lab relay URL is invalid".to_owned());
    }
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve lab relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("immortal-lab refuses non-loopback relay addresses".to_owned());
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_loopback_and_non_ws_targets() {
        assert!(loopback_addresses("wss://relay.example.com").is_err());
        assert!(loopback_addresses("ws://relay.example.com:8080").is_err());
        assert!(loopback_addresses("ws://user@127.0.0.1:8080").is_err());
        assert!(loopback_addresses("ws://127.0.0.1:8080?x=1").is_err());
        assert!(loopback_addresses("http://127.0.0.1:8080").is_err());
    }

    #[test]
    fn accepts_loopback_targets() {
        let addresses =
            loopback_addresses("ws://127.0.0.1:18080").expect("loopback should be accepted");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
    }
}
