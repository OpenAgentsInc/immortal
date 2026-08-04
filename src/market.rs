//! Transport-neutral NIP-59 wrapping for signed private NIP-MKT records.

use secp256k1::{SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        Event, MktProfileSupport, MktValidatedPrivateRecord, RelaySigner, Tag, is_mkt_private_kind,
        validate_mkt_private_raw,
    },
    nip44,
};

const SEAL_KIND: u16 = 13;
const GIFT_WRAP_KIND: u16 = 1_059;

#[derive(Clone)]
pub struct MarketSigner {
    secret: SecretKey,
    signer: RelaySigner,
}

impl MarketSigner {
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        let secret = SecretKey::from_byte_array(bytes)
            .map_err(|_| "market secret key is invalid".to_owned())?;
        let signer = RelaySigner::from_secret_hex(&lower_hex(&bytes))
            .map_err(|error| format!("market signer is invalid: {error}"))?;
        Ok(Self { secret, signer })
    }

    pub fn pubkey(&self) -> &str {
        self.signer.pubkey()
    }

    pub fn sign(&self, created_at: u64, kind: u16, tags: Vec<Tag>, content: String) -> Event {
        self.signer.sign(created_at, kind, tags, content)
    }

    fn conversation_key(&self, peer: &str) -> Result<[u8; 32], String> {
        let peer = XOnlyPublicKey::from_byte_array(decode_hex_32(peer)?)
            .map_err(|_| "market peer public key is invalid".to_owned())?;
        Ok(nip44::conversation_key(&self.secret, &peer))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WrapMaterial {
    pub seal_created_at: u64,
    pub wrap_created_at: u64,
    pub seal_nonce: [u8; 32],
    pub wrap_nonce: [u8; 32],
    pub wrap_secret: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct WrappedMktRecord {
    pub event: Event,
    pub inner_event_id: String,
}

#[derive(Debug, Clone)]
pub struct DeliveredMktRecord {
    pub wrap_event_id: String,
    pub sender: String,
    pub record: MktValidatedPrivateRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rumor {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Tag>,
    content: String,
}

pub fn wrap_mkt_record(
    raw_signed_event: &[u8],
    sender: &MarketSigner,
    recipient: &str,
    material: WrapMaterial,
) -> Result<WrappedMktRecord, String> {
    let inner: Event = serde_json::from_slice(raw_signed_event)
        .map_err(|error| format!("private MKT record is not an event: {error}"))?;
    inner
        .validate_structure()
        .and_then(|()| inner.validate_crypto())
        .map_err(|error| format!("private MKT record is invalid: {error}"))?;
    if !is_mkt_private_kind(inner.kind) {
        return Err("only private NIP-MKT records may be gift-wrapped".to_owned());
    }
    if inner.pubkey != sender.pubkey() {
        return Err("private MKT record signer does not match wrapping sender".to_owned());
    }
    decode_hex_32(recipient)?;
    let raw = std::str::from_utf8(raw_signed_event)
        .map_err(|_| "private MKT record is not UTF-8".to_owned())?;
    let mut rumor = Rumor {
        id: String::new(),
        pubkey: sender.pubkey().to_owned(),
        created_at: inner.created_at,
        kind: inner.kind,
        tags: vec![Tag::new(vec!["p".to_owned(), recipient.to_owned()])],
        content: raw.to_owned(),
    };
    rumor.id = rumor_id(&rumor)?;
    let rumor_json = serde_json::to_string(&rumor)
        .map_err(|error| format!("failed to serialize MKT rumor: {error}"))?;
    let sender_key = sender.conversation_key(recipient)?;
    let sealed_content = nip44::encrypt(&rumor_json, &sender_key, material.seal_nonce)?;
    let seal = sender.sign(
        material.seal_created_at,
        SEAL_KIND,
        Vec::new(),
        sealed_content,
    );
    let seal_json = serde_json::to_string(&seal)
        .map_err(|error| format!("failed to serialize MKT seal: {error}"))?;
    let one_time = MarketSigner::from_secret_bytes(material.wrap_secret)?;
    if one_time.pubkey() == sender.pubkey() {
        return Err("gift-wrap key must be distinct from the sender key".to_owned());
    }
    let wrap_key = one_time.conversation_key(recipient)?;
    let wrap_content = nip44::encrypt(&seal_json, &wrap_key, material.wrap_nonce)?;
    let event = one_time.sign(
        material.wrap_created_at,
        GIFT_WRAP_KIND,
        vec![Tag::new(vec!["p".to_owned(), recipient.to_owned()])],
        wrap_content,
    );
    Ok(WrappedMktRecord {
        event,
        inner_event_id: inner.id,
    })
}

pub fn unwrap_mkt_record(
    wrap: &Event,
    recipient: &MarketSigner,
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<DeliveredMktRecord, String> {
    wrap.validate_structure()
        .and_then(|()| wrap.validate_crypto())
        .map_err(|error| format!("gift wrap is invalid: {error}"))?;
    if wrap.kind != GIFT_WRAP_KIND {
        return Err("wrapped MKT record must use kind 1059".to_owned());
    }
    require_recipient(wrap, recipient.pubkey(), "gift wrap")?;
    let wrap_key = recipient.conversation_key(&wrap.pubkey)?;
    let seal_json = nip44::decrypt(&wrap.content, &wrap_key)?;
    let seal: Event = serde_json::from_str(&seal_json)
        .map_err(|error| format!("gift wrap seal is not an event: {error}"))?;
    seal.validate_structure()
        .and_then(|()| seal.validate_crypto())
        .map_err(|error| format!("gift wrap seal is invalid: {error}"))?;
    if seal.kind != SEAL_KIND || !seal.tags.is_empty() {
        return Err("gift wrap seal must be kind 13 with no tags".to_owned());
    }
    let seal_key = recipient.conversation_key(&seal.pubkey)?;
    let rumor_json = nip44::decrypt(&seal.content, &seal_key)?;
    let rumor: Rumor = serde_json::from_str(&rumor_json)
        .map_err(|error| format!("gift wrap rumor is invalid: {error}"))?;
    if rumor.id != rumor_id(&rumor)? {
        return Err("gift wrap rumor ID is invalid".to_owned());
    }
    if rumor.pubkey != seal.pubkey {
        return Err("gift wrap rumor author does not match the seal signer".to_owned());
    }
    require_rumor_recipient(&rumor, recipient.pubkey())?;
    let record = validate_mkt_private_raw(rumor.content.as_bytes(), supported_profiles)
        .map_err(|error| format!("wrapped private MKT record is invalid: {error}"))?;
    if record.event.pubkey != rumor.pubkey
        || record.event.kind != rumor.kind
        || record.event.created_at != rumor.created_at
    {
        return Err("wrapped private MKT record does not match its rumor".to_owned());
    }
    Ok(DeliveredMktRecord {
        wrap_event_id: wrap.id.clone(),
        sender: seal.pubkey,
        record,
    })
}

fn rumor_id(rumor: &Rumor) -> Result<String, String> {
    Event {
        id: String::new(),
        pubkey: rumor.pubkey.clone(),
        created_at: rumor.created_at,
        kind: rumor.kind,
        tags: rumor.tags.clone(),
        content: rumor.content.clone(),
        sig: String::new(),
    }
    .computed_id()
    .map_err(|error| format!("failed to compute rumor ID: {error}"))
}

fn require_recipient(event: &Event, recipient: &str, layer: &str) -> Result<(), String> {
    let recipients = event.tag_values("p").collect::<Vec<_>>();
    if recipients.as_slice() == [recipient] && event.tags.len() == 1 {
        Ok(())
    } else {
        Err(format!("{layer} must contain exactly one recipient tag"))
    }
}

fn require_rumor_recipient(rumor: &Rumor, recipient: &str) -> Result<(), String> {
    if rumor.tags.len() == 1 && rumor.tags[0].as_slice() == ["p".to_owned(), recipient.to_owned()] {
        Ok(())
    } else {
        Err("gift wrap rumor must contain exactly one recipient tag".to_owned())
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err("market public key must be 64 lowercase hexadecimal characters".to_owned());
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("market hexadecimal value is invalid".to_owned()),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::domain::{MKT_ENVELOPE_SCHEMA, MKT_RFQ_KIND};

    #[test]
    fn nip59_round_trip_preserves_exact_signed_record() {
        let sender = MarketSigner::from_secret_bytes([1; 32]).unwrap();
        let recipient = MarketSigner::from_secret_bytes([2; 32]).unwrap();
        let session = "11".repeat(32);
        let event = sender.sign(
            10,
            MKT_RFQ_KIND,
            vec![
                Tag::new(vec!["d".into(), "22".repeat(32)]),
                Tag::new(vec!["session".into(), session.clone()]),
                Tag::new(vec!["profile".into(), "local-dev".into(), "1".into()]),
                Tag::new(vec![
                    "p".into(),
                    recipient.pubkey().into(),
                    "".into(),
                    "provider".into(),
                ]),
                Tag::new(vec!["alt".into(), "Local development RFQ".into()]),
            ],
            json!({
                "schema": MKT_ENVELOPE_SCHEMA,
                "profile": "local-dev",
                "profile_version": 1,
                "session_id": session
            })
            .to_string(),
        );
        let raw = serde_json::to_vec(&event).unwrap();
        let wrapped = wrap_mkt_record(
            &raw,
            &sender,
            recipient.pubkey(),
            WrapMaterial {
                seal_created_at: 8,
                wrap_created_at: 9,
                seal_nonce: [3; 32],
                wrap_nonce: [4; 32],
                wrap_secret: [5; 32],
            },
        )
        .unwrap();
        let profiles = [MktProfileSupport {
            profile_id: "local-dev",
            version: 1,
            critical_members: &[],
            understood_members: &[],
        }];
        let delivered = unwrap_mkt_record(&wrapped.event, &recipient, &profiles).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/nipmkt/client-transport.json"
        ))
        .unwrap();
        assert_eq!(
            event.id,
            fixture["deterministic_round_trip"]["inner_event_id"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            wrapped.event.id,
            fixture["deterministic_round_trip"]["outer_event_id"]
                .as_str()
                .unwrap()
        );
        assert_eq!(delivered.sender, sender.pubkey());
        assert_eq!(delivered.record.raw_signed_event, raw);
    }
}
