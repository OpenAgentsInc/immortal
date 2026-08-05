//! Transport-neutral NIP-59 wrapping for signed private NIP-MKT records.

use secp256k1::{SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        Event, MktProfileSupport, MktValidatedPrivateRecord, RelaySigner, Tag, is_mkt_private_kind,
        parse_json_without_duplicate_members, validate_mkt_private_raw,
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

    #[cfg(feature = "server")]
    #[doc(hidden)]
    pub fn from_relay_signer(signer: RelaySigner) -> Self {
        Self {
            secret: signer.secret_key(),
            signer,
        }
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

#[derive(Debug, Clone, Copy)]
pub struct ExternalWrapMaterial {
    pub seal_created_at: u64,
    pub wrap_created_at: u64,
    pub seal_nonce: [u8; 32],
    pub wrap_nonce: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct MarketEventSigningRequest {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
}

impl MarketEventSigningRequest {
    pub fn verify_signed(&self, event: Event) -> Result<Event, String> {
        if event.pubkey != self.pubkey
            || event.created_at != self.created_at
            || event.kind != self.kind
            || event.tags != self.tags
            || event.content != self.content
        {
            return Err("external signer changed the requested market event".to_owned());
        }
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .map_err(|error| format!("external market signature is invalid: {error}"))?;
        Ok(event)
    }
}

#[derive(Debug, Clone)]
pub struct Nip44EncryptRequest {
    pub actor_pubkey: String,
    pub peer_pubkey: String,
    pub plaintext: String,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Nip44DecryptRequest {
    pub recipient_pubkey: String,
    pub peer_pubkey: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone)]
pub struct WrappedMktRecord {
    pub event: Event,
    pub inner_event_id: String,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeliveredMktRecord {
    wrap_event_id: String,
    sender: String,
    record: MktValidatedPrivateRecord,
    raw_wrap_event: Option<Vec<u8>>,
}

impl DeliveredMktRecord {
    pub fn wrap_event_id(&self) -> &str {
        &self.wrap_event_id
    }

    pub fn sender(&self) -> &str {
        &self.sender
    }

    pub fn record(&self) -> &MktValidatedPrivateRecord {
        &self.record
    }

    pub fn raw_wrap_event(&self) -> Option<&[u8]> {
        self.raw_wrap_event.as_deref()
    }
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
    let one_time = MarketSigner::from_secret_bytes(material.wrap_secret)?;
    let external_material = ExternalWrapMaterial {
        seal_created_at: material.seal_created_at,
        wrap_created_at: material.wrap_created_at,
        seal_nonce: material.seal_nonce,
        wrap_nonce: material.wrap_nonce,
    };
    wrap_mkt_record_with_callbacks(
        raw_signed_event,
        sender.pubkey(),
        recipient,
        one_time.pubkey(),
        external_material,
        |request| {
            let signer = if request.pubkey == sender.pubkey() {
                sender
            } else if request.pubkey == one_time.pubkey() {
                &one_time
            } else {
                return Err("market signing request names an unknown key".to_owned());
            };
            Ok(signer.sign(
                request.created_at,
                request.kind,
                request.tags.clone(),
                request.content.clone(),
            ))
        },
        |request| {
            let signer = if request.actor_pubkey == sender.pubkey() {
                sender
            } else if request.actor_pubkey == one_time.pubkey() {
                &one_time
            } else {
                return Err("NIP-44 request names an unknown market key".to_owned());
            };
            let key = signer.conversation_key(&request.peer_pubkey)?;
            nip44::encrypt(&request.plaintext, &key, request.nonce)
        },
    )
}

pub fn wrap_mkt_record_with_callbacks<Sign, Encrypt>(
    raw_signed_event: &[u8],
    sender_pubkey: &str,
    recipient: &str,
    wrapper_pubkey: &str,
    material: ExternalWrapMaterial,
    mut sign_event: Sign,
    mut encrypt: Encrypt,
) -> Result<WrappedMktRecord, String>
where
    Sign: FnMut(&MarketEventSigningRequest) -> Result<Event, String>,
    Encrypt: FnMut(&Nip44EncryptRequest) -> Result<String, String>,
{
    let inner: Event = serde_json::from_slice(raw_signed_event)
        .map_err(|error| format!("private MKT record is not an event: {error}"))?;
    inner
        .validate_structure()
        .and_then(|()| inner.validate_crypto())
        .map_err(|error| format!("private MKT record is invalid: {error}"))?;
    if !is_mkt_private_kind(inner.kind) {
        return Err("only private NIP-MKT records may be gift-wrapped".to_owned());
    }
    if inner.pubkey != sender_pubkey {
        return Err("private MKT record signer does not match wrapping sender".to_owned());
    }
    decode_hex_32(recipient)?;
    decode_hex_32(sender_pubkey)?;
    decode_hex_32(wrapper_pubkey)?;
    if wrapper_pubkey == sender_pubkey {
        return Err("gift-wrap key must be distinct from the sender key".to_owned());
    }
    let raw = std::str::from_utf8(raw_signed_event)
        .map_err(|_| "private MKT record is not UTF-8".to_owned())?;
    let mut rumor = Rumor {
        id: String::new(),
        pubkey: sender_pubkey.to_owned(),
        created_at: inner.created_at,
        kind: inner.kind,
        tags: vec![Tag::new(vec!["p".to_owned(), recipient.to_owned()])],
        content: raw.to_owned(),
    };
    rumor.id = rumor_id(&rumor)?;
    let rumor_json = serde_json::to_string(&rumor)
        .map_err(|error| format!("failed to serialize MKT rumor: {error}"))?;
    let sealed_content = encrypt(&Nip44EncryptRequest {
        actor_pubkey: sender_pubkey.to_owned(),
        peer_pubkey: recipient.to_owned(),
        plaintext: rumor_json,
        nonce: material.seal_nonce,
    })?;
    let seal_request = MarketEventSigningRequest {
        pubkey: sender_pubkey.to_owned(),
        created_at: material.seal_created_at,
        kind: SEAL_KIND,
        tags: Vec::new(),
        content: sealed_content,
    };
    let seal = seal_request.verify_signed(sign_event(&seal_request)?)?;
    let seal_json = serde_json::to_string(&seal)
        .map_err(|error| format!("failed to serialize MKT seal: {error}"))?;
    let wrap_content = encrypt(&Nip44EncryptRequest {
        actor_pubkey: wrapper_pubkey.to_owned(),
        peer_pubkey: recipient.to_owned(),
        plaintext: seal_json,
        nonce: material.wrap_nonce,
    })?;
    let wrap_request = MarketEventSigningRequest {
        pubkey: wrapper_pubkey.to_owned(),
        created_at: material.wrap_created_at,
        kind: GIFT_WRAP_KIND,
        tags: vec![Tag::new(vec!["p".to_owned(), recipient.to_owned()])],
        content: wrap_content,
    };
    let event = wrap_request.verify_signed(sign_event(&wrap_request)?)?;
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
    unwrap_mkt_record_with_callback(wrap, recipient.pubkey(), supported_profiles, |request| {
        let key = recipient.conversation_key(&request.peer_pubkey)?;
        nip44::decrypt(&request.ciphertext, &key)
    })
}

pub fn unwrap_mkt_record_raw(
    raw_wrap_event: &[u8],
    recipient: &MarketSigner,
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<DeliveredMktRecord, String> {
    unwrap_mkt_record_raw_with_callback(
        raw_wrap_event,
        recipient.pubkey(),
        supported_profiles,
        |request| {
            let key = recipient.conversation_key(&request.peer_pubkey)?;
            nip44::decrypt(&request.ciphertext, &key)
        },
    )
}

pub fn unwrap_mkt_record_raw_with_callback<Decrypt>(
    raw_wrap_event: &[u8],
    recipient_pubkey: &str,
    supported_profiles: &[MktProfileSupport<'_>],
    decrypt: Decrypt,
) -> Result<DeliveredMktRecord, String>
where
    Decrypt: FnMut(&Nip44DecryptRequest) -> Result<String, String>,
{
    if raw_wrap_event.is_empty() || raw_wrap_event.len() > 512 * 1024 {
        return Err("gift wrap bytes are empty or exceed their bound".to_owned());
    }
    let raw_text = std::str::from_utf8(raw_wrap_event)
        .map_err(|_| "gift wrap bytes are not UTF-8".to_owned())?;
    let value = parse_json_without_duplicate_members(raw_text, "gift wrap event")?;
    let event: Event = serde_json::from_value(value)
        .map_err(|error| format!("gift wrap bytes are not an event: {error}"))?;
    let mut delivered =
        unwrap_mkt_record_with_callback(&event, recipient_pubkey, supported_profiles, decrypt)?;
    delivered.raw_wrap_event = Some(raw_wrap_event.to_vec());
    Ok(delivered)
}

pub fn unwrap_mkt_record_with_callback<Decrypt>(
    wrap: &Event,
    recipient_pubkey: &str,
    supported_profiles: &[MktProfileSupport<'_>],
    decrypt: Decrypt,
) -> Result<DeliveredMktRecord, String>
where
    Decrypt: FnMut(&Nip44DecryptRequest) -> Result<String, String>,
{
    let rumor = unwrap_rumor_with_callback(wrap, recipient_pubkey, decrypt)?;
    validate_rumor_record(wrap, rumor, supported_profiles)
}

/// Probe a handler-addressed NIP-59 delivery without claiming every delivery
/// to the relay key as MKT-SWP. Non-MKT rumors remain opaque transport.
#[cfg(feature = "server")]
#[doc(hidden)]
pub fn unwrap_mkt_record_for_handler(
    wrap: &Event,
    recipient: &MarketSigner,
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<Option<DeliveredMktRecord>, String> {
    let rumor = unwrap_rumor(wrap, recipient)?;
    if !is_mkt_private_kind(rumor.kind) {
        return Ok(None);
    }
    validate_rumor_record(wrap, rumor, supported_profiles).map(Some)
}

#[cfg(feature = "server")]
fn unwrap_rumor(wrap: &Event, recipient: &MarketSigner) -> Result<Rumor, String> {
    unwrap_rumor_with_callback(wrap, recipient.pubkey(), |request| {
        let key = recipient.conversation_key(&request.peer_pubkey)?;
        nip44::decrypt(&request.ciphertext, &key)
    })
}

fn unwrap_rumor_with_callback<Decrypt>(
    wrap: &Event,
    recipient_pubkey: &str,
    mut decrypt: Decrypt,
) -> Result<Rumor, String>
where
    Decrypt: FnMut(&Nip44DecryptRequest) -> Result<String, String>,
{
    wrap.validate_structure()
        .and_then(|()| wrap.validate_crypto())
        .map_err(|error| format!("gift wrap is invalid: {error}"))?;
    if wrap.kind != GIFT_WRAP_KIND {
        return Err("wrapped MKT record must use kind 1059".to_owned());
    }
    decode_hex_32(recipient_pubkey)?;
    require_recipient(wrap, recipient_pubkey, "gift wrap")?;
    let seal_json = decrypt(&Nip44DecryptRequest {
        recipient_pubkey: recipient_pubkey.to_owned(),
        peer_pubkey: wrap.pubkey.clone(),
        ciphertext: wrap.content.clone(),
    })?;
    let seal: Event = serde_json::from_str(&seal_json)
        .map_err(|error| format!("gift wrap seal is not an event: {error}"))?;
    seal.validate_structure()
        .and_then(|()| seal.validate_crypto())
        .map_err(|error| format!("gift wrap seal is invalid: {error}"))?;
    if seal.kind != SEAL_KIND || !seal.tags.is_empty() {
        return Err("gift wrap seal must be kind 13 with no tags".to_owned());
    }
    let rumor_json = decrypt(&Nip44DecryptRequest {
        recipient_pubkey: recipient_pubkey.to_owned(),
        peer_pubkey: seal.pubkey.clone(),
        ciphertext: seal.content.clone(),
    })?;
    let rumor: Rumor = serde_json::from_str(&rumor_json)
        .map_err(|error| format!("gift wrap rumor is invalid: {error}"))?;
    if rumor.id != rumor_id(&rumor)? {
        return Err("gift wrap rumor ID is invalid".to_owned());
    }
    if rumor.pubkey != seal.pubkey {
        return Err("gift wrap rumor author does not match the seal signer".to_owned());
    }
    require_rumor_recipient(&rumor, recipient_pubkey)?;
    Ok(rumor)
}

fn validate_rumor_record(
    wrap: &Event,
    rumor: Rumor,
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<DeliveredMktRecord, String> {
    let record = validate_mkt_private_raw(rumor.content.as_bytes(), supported_profiles)
        .map_err(|error| format!("wrapped private MKT record is invalid: {error}"))?;
    if record.event().pubkey != rumor.pubkey
        || record.event().kind != rumor.kind
        || record.event().created_at != rumor.created_at
    {
        return Err("wrapped private MKT record does not match its rumor".to_owned());
    }
    Ok(DeliveredMktRecord {
        wrap_event_id: wrap.id.clone(),
        sender: rumor.pubkey,
        record,
        raw_wrap_event: None,
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
            "../../../tests/fixtures/nipmkt/client-transport.json"
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
        assert_eq!(delivered.sender(), sender.pubkey());
        assert_eq!(delivered.record().raw_signed_event(), raw);
    }

    #[test]
    fn external_sign_encrypt_and_decrypt_callbacks_need_no_secret_material() {
        let sender = MarketSigner::from_secret_bytes([1; 32]).unwrap();
        let recipient = MarketSigner::from_secret_bytes([2; 32]).unwrap();
        let wrapper = MarketSigner::from_secret_bytes([5; 32]).unwrap();
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
        let wrapped = wrap_mkt_record_with_callbacks(
            &raw,
            sender.pubkey(),
            recipient.pubkey(),
            wrapper.pubkey(),
            ExternalWrapMaterial {
                seal_created_at: 8,
                wrap_created_at: 9,
                seal_nonce: [3; 32],
                wrap_nonce: [4; 32],
            },
            |request| {
                let signer = if request.pubkey == sender.pubkey() {
                    &sender
                } else if request.pubkey == wrapper.pubkey() {
                    &wrapper
                } else {
                    return Err("unexpected signing identity".to_owned());
                };
                Ok(signer.sign(
                    request.created_at,
                    request.kind,
                    request.tags.clone(),
                    request.content.clone(),
                ))
            },
            |request| {
                let actor = if request.actor_pubkey == sender.pubkey() {
                    &sender
                } else if request.actor_pubkey == wrapper.pubkey() {
                    &wrapper
                } else {
                    return Err("unexpected encryption identity".to_owned());
                };
                nip44::encrypt(
                    &request.plaintext,
                    &actor.conversation_key(&request.peer_pubkey)?,
                    request.nonce,
                )
            },
        )
        .unwrap();
        let profiles = [MktProfileSupport {
            profile_id: "local-dev",
            version: 1,
            critical_members: &[],
            understood_members: &[],
        }];
        let delivered = unwrap_mkt_record_with_callback(
            &wrapped.event,
            recipient.pubkey(),
            &profiles,
            |request| {
                nip44::decrypt(
                    &request.ciphertext,
                    &recipient.conversation_key(&request.peer_pubkey)?,
                )
            },
        )
        .unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/client-transport.json"
        ))
        .unwrap();
        assert_eq!(
            wrapped.event.id,
            fixture["external_callback_round_trip"]["outer_event_id"]
        );
        assert_eq!(delivered.record().raw_signed_event(), raw);
    }

    #[test]
    #[cfg(feature = "server")]
    fn handler_probe_leaves_non_mkt_nip59_delivery_opaque() {
        let sender = MarketSigner::from_secret_bytes([31; 32]).unwrap();
        let recipient = MarketSigner::from_secret_bytes([32; 32]).unwrap();
        let inner = sender.sign(
            20,
            14,
            vec![Tag::new(vec!["p".into(), recipient.pubkey().into()])],
            "ordinary direct message".into(),
        );
        let mut rumor = Rumor {
            id: String::new(),
            pubkey: sender.pubkey().into(),
            created_at: inner.created_at,
            kind: inner.kind,
            tags: vec![Tag::new(vec!["p".into(), recipient.pubkey().into()])],
            content: serde_json::to_string(&inner).unwrap(),
        };
        rumor.id = rumor_id(&rumor).unwrap();
        let sender_key = sender.conversation_key(recipient.pubkey()).unwrap();
        let sealed_content = nip44::encrypt(
            &serde_json::to_string(&rumor).unwrap(),
            &sender_key,
            [33; 32],
        )
        .unwrap();
        let seal = sender.sign(19, SEAL_KIND, Vec::new(), sealed_content);
        let one_time = MarketSigner::from_secret_bytes([34; 32]).unwrap();
        let wrap_key = one_time.conversation_key(recipient.pubkey()).unwrap();
        let wrap_content =
            nip44::encrypt(&serde_json::to_string(&seal).unwrap(), &wrap_key, [35; 32]).unwrap();
        let wrap = one_time.sign(
            20,
            GIFT_WRAP_KIND,
            vec![Tag::new(vec!["p".into(), recipient.pubkey().into()])],
            wrap_content,
        );

        assert!(
            unwrap_mkt_record_for_handler(&wrap, &recipient, &[])
                .unwrap()
                .is_none()
        );
    }
}
