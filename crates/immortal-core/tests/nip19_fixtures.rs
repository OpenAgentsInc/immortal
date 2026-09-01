//! Fixture-backed NIP-19 bare-key encoding coverage.

use immortal_core::nip19::{Nip19Error, decode_npub, decode_nsec, encode_npub, encode_nsec};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    #[allow(dead_code)]
    source: String,
    valid: Vec<ValidCase>,
    invalid: Vec<InvalidCase>,
    wrong_prefix: Vec<WrongPrefixCase>,
}

#[derive(Deserialize)]
struct ValidCase {
    encoded: String,
    hex: String,
}

#[derive(Deserialize)]
struct InvalidCase {
    encoded: String,
    reason: String,
}

#[derive(Deserialize)]
struct WrongPrefixCase {
    encoded: String,
    decode_as: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../../tests/fixtures/nip19/keys.json")).unwrap()
}

fn hex_bytes(hex: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

#[test]
fn nip19_keys_round_trip() {
    for case in fixture().valid {
        let bytes = hex_bytes(&case.hex);
        if case.encoded.starts_with("npub") {
            assert_eq!(encode_npub(&bytes), case.encoded);
            assert_eq!(decode_npub(&case.encoded).unwrap(), bytes);
            assert_eq!(
                decode_npub(&case.encoded.to_ascii_uppercase()).unwrap(),
                bytes
            );
        } else {
            assert_eq!(encode_nsec(&bytes), case.encoded);
            assert_eq!(decode_nsec(&case.encoded).unwrap(), bytes);
        }
    }
}

#[test]
fn nip19_invalid_strings_are_refused() {
    for case in fixture().invalid {
        let decoded = if case.encoded.starts_with("nsec") {
            decode_nsec(&case.encoded).map(|_| ())
        } else {
            decode_npub(&case.encoded).map(|_| ())
        };
        assert!(decoded.is_err(), "{}: {}", case.encoded, case.reason);
    }
}

#[test]
fn nip19_prefix_selects_the_key_kind() {
    for case in fixture().wrong_prefix {
        let decoded = match case.decode_as.as_str() {
            "npub" => decode_npub(&case.encoded).map(|_| ()),
            "nsec" => decode_nsec(&case.encoded).map(|_| ()),
            other => panic!("unknown prefix {other}"),
        };
        assert!(
            matches!(decoded, Err(Nip19Error::WrongPrefix { .. })),
            "{}",
            case.encoded
        );
    }
}
