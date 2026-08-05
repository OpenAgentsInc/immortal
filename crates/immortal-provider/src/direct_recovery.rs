use std::{
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use immortal_core::{
    domain::{Event, parse_unique_json},
    market::MarketSigner,
};
use serde::{Deserialize, Serialize};

pub(crate) const REQUEST_SCHEMA: &str = "openagents.immortal.provider-direct-recovery-request.v1";
pub(crate) const RESPONSE_SCHEMA: &str = "openagents.immortal.provider-direct-recovery-response.v1";
pub(crate) const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_REQUEST_WRAPS: usize = 32;
pub(crate) const MAX_RESPONSE_WRAPS: usize = 512;
pub(crate) const MAX_CONNECTIONS_PER_POLL: usize = 4;
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectRecoveryRequest {
    schema: String,
    wraps: Vec<Event>,
}

impl DirectRecoveryRequest {
    pub(crate) fn into_wraps(self) -> Result<Vec<Event>, String> {
        if self.schema != REQUEST_SCHEMA {
            return Err("direct recovery request schema is unsupported".to_owned());
        }
        if self.wraps.is_empty() || self.wraps.len() > MAX_REQUEST_WRAPS {
            return Err(format!(
                "direct recovery request must contain 1-{MAX_REQUEST_WRAPS} wraps"
            ));
        }
        Ok(self.wraps)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DirectRecoveryResponse<'a> {
    schema: &'static str,
    wraps: &'a [Event],
}

pub(crate) struct DirectRecoveryListener {
    listener: TcpListener,
}

impl DirectRecoveryListener {
    pub(crate) fn bind(address: SocketAddr) -> Result<Self, String> {
        if !private_or_loopback(address.ip()) {
            return Err("direct recovery listener requires a private or loopback bind".to_owned());
        }
        let listener = TcpListener::bind(address)
            .map_err(|error| format!("could not bind direct recovery listener: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure direct recovery listener: {error}"))?;
        Ok(Self { listener })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|error| format!("could not inspect direct recovery listener: {error}"))
    }

    pub(crate) fn accept(&self) -> Result<Option<TcpStream>, String> {
        let (stream, peer) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "could not accept direct recovery connection: {error}"
                ));
            }
        };
        if !private_or_loopback(peer.ip()) {
            return Err("direct recovery refused a non-private peer".to_owned());
        }
        stream
            .set_read_timeout(Some(CONNECTION_TIMEOUT))
            .map_err(|error| format!("could not set direct recovery read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(CONNECTION_TIMEOUT))
            .map_err(|error| format!("could not set direct recovery write timeout: {error}"))?;
        Ok(Some(stream))
    }
}

pub(crate) fn read_request(stream: &mut TcpStream) -> Result<DirectRecoveryRequest, String> {
    let payload = read_frame(stream, MAX_REQUEST_BYTES)?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| "direct recovery request is not UTF-8".to_owned())?;
    let value = parse_unique_json(text, "direct recovery request")?;
    validate_request_shape(&value)?;
    serde_json::from_value(value)
        .map_err(|error| format!("direct recovery request has an invalid shape: {error}"))
}

fn validate_request_shape(value: &serde_json::Value) -> Result<(), String> {
    let request = value
        .as_object()
        .filter(|request| {
            request.len() == 2 && request.contains_key("schema") && request.contains_key("wraps")
        })
        .ok_or_else(|| "direct recovery request has unknown or missing members".to_owned())?;
    let wraps = request
        .get("wraps")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "direct recovery wraps must be an array".to_owned())?;
    for wrap in wraps {
        let wrap = wrap
            .as_object()
            .filter(|wrap| {
                wrap.len() == 7
                    && [
                        "id",
                        "pubkey",
                        "created_at",
                        "kind",
                        "tags",
                        "content",
                        "sig",
                    ]
                    .iter()
                    .all(|member| wrap.contains_key(*member))
            })
            .ok_or_else(|| "direct recovery gift wrap has unknown or missing members".to_owned())?;
        if !wrap.get("tags").is_some_and(serde_json::Value::is_array) {
            return Err("direct recovery gift wrap tags must be an array".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn write_response(stream: &mut TcpStream, wraps: &[Event]) -> Result<(), String> {
    if wraps.len() > MAX_RESPONSE_WRAPS {
        return Err(format!(
            "direct recovery response exceeds its {MAX_RESPONSE_WRAPS}-wrap bound"
        ));
    }
    let payload = serde_json::to_vec(&DirectRecoveryResponse {
        schema: RESPONSE_SCHEMA,
        wraps,
    })
    .map_err(|error| format!("could not serialize direct recovery response: {error}"))?;
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "direct recovery response exceeds its {MAX_RESPONSE_BYTES}-byte bound"
        ));
    }
    write_frame(stream, &payload)
}

fn read_frame(reader: &mut impl Read, maximum_bytes: usize) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| format!("could not read direct recovery frame length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "direct recovery frame length is unsupported".to_owned())?;
    if length == 0 || length > maximum_bytes {
        return Err(format!(
            "direct recovery frame must contain 1-{maximum_bytes} bytes"
        ));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("could not read direct recovery frame payload: {error}"))?;
    Ok(payload)
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), String> {
    let length = u32::try_from(payload.len())
        .map_err(|_| "direct recovery response length is unsupported".to_owned())?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("could not write direct recovery response: {error}"))
}

pub(crate) fn wrap_response_record(
    signer: &MarketSigner,
    requester_pubkey: &str,
    record: &Event,
    material: immortal_core::market::WrapMaterial,
) -> Result<Event, String> {
    let raw = serde_json::to_vec(record)
        .map_err(|error| format!("could not serialize provider recovery record: {error}"))?;
    immortal_core::market::wrap_mkt_record(&raw, signer, requester_pubkey, material)
        .map(|wrapped| wrapped.event)
}

fn private_or_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_frame_is_length_bounded_and_rejects_duplicate_json_members() {
        let payload = format!(r#"{{"schema":"{REQUEST_SCHEMA}","wraps":[]}}"#);
        let mut framed = Vec::new();
        write_frame(&mut framed, payload.as_bytes()).expect("frame request");
        let decoded = read_frame(&mut Cursor::new(framed), MAX_REQUEST_BYTES).expect("read frame");
        let value = parse_unique_json(
            std::str::from_utf8(&decoded).expect("UTF-8"),
            "direct recovery request",
        )
        .expect("unique JSON");
        let request: DirectRecoveryRequest = serde_json::from_value(value).expect("request shape");
        assert!(request.into_wraps().is_err());

        let duplicate =
            format!(r#"{{"schema":"{REQUEST_SCHEMA}","schema":"{REQUEST_SCHEMA}","wraps":[]}}"#);
        assert!(parse_unique_json(&duplicate, "direct recovery request").is_err());

        let mut oversized = Cursor::new(
            u32::try_from(MAX_REQUEST_BYTES + 1)
                .expect("request bound fits u32")
                .to_be_bytes(),
        );
        assert!(read_frame(&mut oversized, MAX_REQUEST_BYTES).is_err());
    }

    #[test]
    fn listener_refuses_public_binds() {
        assert!(DirectRecoveryListener::bind("192.0.2.1:1".parse().expect("address")).is_err());
    }

    #[test]
    fn request_shape_is_closed_over_the_envelope_and_wraps() {
        let unknown = serde_json::json!({
            "schema":REQUEST_SCHEMA,
            "wraps":[],
            "unknown":true,
        });
        assert!(validate_request_shape(&unknown).is_err());
        let unknown_wrap = serde_json::json!({
            "schema":REQUEST_SCHEMA,
            "wraps":[{
                "id":"00",
                "pubkey":"00",
                "created_at":0,
                "kind":1059,
                "tags":[],
                "content":"",
                "sig":"00",
                "unknown":true,
            }],
        });
        assert!(validate_request_shape(&unknown_wrap).is_err());
    }
}
