//! Official BIP-327 test-vector replay against the in-repo MuSig2 implementation.
//!
//! Provenance and the replay/gap table live in `tests/fixtures/bip327/README.md`.
//! This file drives only the public `mkt_swp_verify` API. Vectors that fix a
//! secret nonce, or that assert the exact aggregate-nonce serialization, are
//! replayed from the `#[cfg(test)]` module inside `mkt_swp_verify.rs`, because
//! exposing either input publicly would let a caller inject a nonce in
//! production.

use immortal_core::mkt_swp_verify::{
    Musig2Tweak, VerificationError, musig2_aggregate_key, musig2_aggregate_partial_signatures,
    musig2_nonce_gen, musig2_tweaked_aggregate_key, verify_musig2_partial_signature,
    verify_musig2_partial_signature_with_tweaks,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;

const KEY_AGG: &str = include_str!("../../../tests/fixtures/bip327/key_agg_vectors.json");
const NONCE_GEN: &str = include_str!("../../../tests/fixtures/bip327/nonce_gen_vectors.json");
const NONCE_AGG: &str = include_str!("../../../tests/fixtures/bip327/nonce_agg_vectors.json");
const SIGN_VERIFY: &str = include_str!("../../../tests/fixtures/bip327/sign_verify_vectors.json");
const SIG_AGG: &str = include_str!("../../../tests/fixtures/bip327/sig_agg_vectors.json");
const TWEAK: &str = include_str!("../../../tests/fixtures/bip327/tweak_vectors.json");
const DET_SIGN: &str = include_str!("../../../tests/fixtures/bip327/det_sign_vectors.json");

// ---------------------------------------------------------------- KeyAgg ----

#[test]
fn bip327_key_aggregation_valid_vectors() {
    let vectors = parse(KEY_AGG);
    let cases = array(&vectors["valid_test_cases"]);
    assert_eq!(cases.len(), 4, "upstream key_agg valid case count changed");

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let aggregate = musig2_aggregate_key(&keys)
            .unwrap_or_else(|error| panic!("key_agg valid case {case_index} failed: {error}"));
        assert_eq!(
            hex_upper(&aggregate.serialize()),
            text(&case["expected"]),
            "key_agg valid case {case_index} produced the wrong aggregate key",
        );
    }
}

#[test]
fn bip327_key_aggregation_error_vectors() {
    let vectors = parse(KEY_AGG);
    let cases = array(&vectors["error_test_cases"]);
    assert_eq!(cases.len(), 5, "upstream key_agg error case count changed");

    let mut invalid_contribution = 0;
    let mut value_errors = 0;

    for (case_index, case) in cases.iter().enumerate() {
        let indices = array(&case["key_indices"]);
        let error_type = text(&case["error"]["type"]);

        if error_type == "invalid_contribution" {
            // The offending contribution is a public key that is not a valid
            // point. Immortal never materialises such a key: `PublicKey` is
            // parsed at the boundary, so the refusal happens before
            // aggregation rather than inside it.
            assert_eq!(text(&case["error"]["contrib"]), "pubkey");
            let signer = usize::try_from(unsigned(&case["error"]["signer"])).unwrap();
            for (position, index) in indices.iter().enumerate() {
                let encoded = fixed::<33>(text(&vectors["pubkeys"][usize_of(index)]));
                let parsed = PublicKey::from_slice(&encoded);
                if position == signer {
                    assert!(
                        parsed.is_err(),
                        "key_agg error case {case_index} expected signer {signer} to be refused",
                    );
                } else {
                    assert!(
                        parsed.is_ok(),
                        "key_agg error case {case_index} refused an honest signer",
                    );
                }
            }
            invalid_contribution += 1;
            continue;
        }

        assert_eq!(error_type, "value");
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let tweaks = parse_tweaks(
            &vectors["tweaks"],
            &case["tweak_indices"],
            &case["is_xonly"],
        );
        let outcome = musig2_tweaked_aggregate_key(&keys, &tweaks);
        assert!(
            matches!(outcome, Err(VerificationError::Crypto(_))),
            "key_agg error case {case_index} ({}) was accepted: {outcome:?}",
            text(&case["comment"]),
        );
        value_errors += 1;
    }

    assert_eq!(invalid_contribution, 3);
    assert_eq!(value_errors, 2);
}

// ----------------------------------------------------------------- Tweak ----

#[test]
fn bip327_tweak_valid_vectors() {
    let vectors = parse(TWEAK);
    let cases = array(&vectors["valid_test_cases"]);
    assert_eq!(cases.len(), 5, "upstream tweak valid case count changed");
    let message = decode(text(&vectors["msg"]));

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let tweaks = parse_tweaks(
            &vectors["tweaks"],
            &case["tweak_indices"],
            &case["is_xonly"],
        );
        let signer_index = usize::try_from(unsigned(&case["signer_index"])).unwrap();
        let expected = fixed::<32>(text(&case["expected"]));

        verify_musig2_partial_signature_with_tweaks(
            &keys,
            &nonces,
            &tweaks,
            signer_index,
            &message,
            &expected,
        )
        .unwrap_or_else(|error| {
            panic!(
                "tweak valid case {case_index} ({}) rejected the official partial signature: {error}",
                text(&case["comment"]),
            )
        });
    }
}

#[test]
fn bip327_tweak_error_vectors() {
    let vectors = parse(TWEAK);
    let cases = array(&vectors["error_test_cases"]);
    assert_eq!(cases.len(), 1, "upstream tweak error case count changed");
    let message = decode(text(&vectors["msg"]));

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let tweaks = parse_tweaks(
            &vectors["tweaks"],
            &case["tweak_indices"],
            &case["is_xonly"],
        );
        let signer_index = usize::try_from(unsigned(&case["signer_index"])).unwrap();

        let aggregate = musig2_tweaked_aggregate_key(&keys, &tweaks);
        assert!(
            matches!(aggregate, Err(VerificationError::Crypto(_))),
            "tweak error case {case_index} produced an aggregate key: {aggregate:?}",
        );
        let verified = verify_musig2_partial_signature_with_tweaks(
            &keys,
            &nonces,
            &tweaks,
            signer_index,
            &message,
            &[0_u8; 32],
        );
        assert!(
            verified.is_err(),
            "tweak error case {case_index} verified under an out-of-range tweak",
        );
    }
}

// -------------------------------------------------------------- NonceGen ----

#[test]
fn bip327_nonce_generation_vectors() {
    let vectors = parse(NONCE_GEN);
    let cases = array(&vectors["test_cases"]);
    assert_eq!(cases.len(), 4, "upstream nonce_gen case count changed");

    let mut replayed = 0;
    let mut skipped = 0;

    for (case_index, case) in cases.iter().enumerate() {
        // `musig2_nonce_gen` requires every input BIP-327 treats as optional.
        // The all-absent case has no representable argument, so it is recorded
        // as a gap rather than approximated.
        if case["sk"].is_null()
            || case["aggpk"].is_null()
            || case["msg"].is_null()
            || case["extra_in"].is_null()
        {
            skipped += 1;
            continue;
        }

        let secret_key = SecretKey::from_byte_array(fixed::<32>(text(&case["sk"]))).unwrap();
        let aggregate_key = fixed::<32>(text(&case["aggpk"]));
        let message = decode(text(&case["msg"]));
        let extra_input = decode(text(&case["extra_in"]));
        let randomness = fixed::<32>(text(&case["rand_"]));

        let nonce = musig2_nonce_gen(
            &secret_key,
            &aggregate_key,
            &message,
            &extra_input,
            randomness,
        )
        .unwrap_or_else(|error| panic!("nonce_gen case {case_index} failed: {error}"));

        assert_eq!(
            hex_upper(&nonce.public_nonce()),
            text(&case["expected_pubnonce"]),
            "nonce_gen case {case_index} produced the wrong public nonce",
        );
        // The public nonce is k1*G || k2*G, so matching it pins both secret
        // nonce scalars without the secret nonce ever leaving the type.
        assert_eq!(
            text(&case["expected_secnonce"])[128..],
            hex_upper(
                &PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret_key).serialize()
            ),
            "nonce_gen case {case_index} vector binds a different signer key",
        );
        replayed += 1;
    }

    assert_eq!(replayed, 3);
    assert_eq!(skipped, 1);
}

// -------------------------------------------------------------- NonceAgg ----

#[test]
fn bip327_nonce_aggregation_error_vectors() {
    // Aggregation itself is internal; its exact output is asserted from the
    // in-module test. What is reachable publicly is the refusal: a malformed
    // public nonce must fail the session before any signature is believed.
    let vectors = parse(NONCE_AGG);
    let cases = array(&vectors["error_test_cases"]);
    assert_eq!(
        cases.len(),
        3,
        "upstream nonce_agg error case count changed"
    );

    let signers = parse(SIGN_VERIFY);
    let keys = parse_keys(&signers["pubkeys"], &json_indices(&[0, 1]));
    let message = decode(text(&signers["msgs"][0]));

    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(text(&case["error"]["contrib"]), "pubnonce");
        let nonces = parse_nonces(&vectors["pnonces"], &case["pnonce_indices"]);
        let outcome = verify_musig2_partial_signature(&keys, &nonces, 0, &message, &[0_u8; 32]);
        assert!(
            matches!(outcome, Err(VerificationError::Crypto(reason)) if reason.contains("public nonce")),
            "nonce_agg error case {case_index} ({}) was not refused as a nonce error: {outcome:?}",
            text(&case["comment"]),
        );
    }
}

// ------------------------------------------------------------ Sign/Verify ----

#[test]
fn bip327_partial_signature_valid_vectors() {
    let vectors = parse(SIGN_VERIFY);
    let cases = array(&vectors["valid_test_cases"]);
    assert_eq!(
        cases.len(),
        6,
        "upstream sign_verify valid case count changed"
    );

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let message = decode(text(&vectors["msgs"][usize_of(&case["msg_index"])]));
        let signer_index = usize::try_from(unsigned(&case["signer_index"])).unwrap();
        let expected = fixed::<32>(text(&case["expected"]));

        verify_musig2_partial_signature(&keys, &nonces, signer_index, &message, &expected)
            .unwrap_or_else(|error| {
                panic!(
                    "sign_verify valid case {case_index} rejected the official partial signature: {error}",
                )
            });
    }
}

#[test]
fn bip327_partial_signature_verify_fail_vectors() {
    let vectors = parse(SIGN_VERIFY);
    let cases = array(&vectors["verify_fail_test_cases"]);
    assert_eq!(cases.len(), 3, "upstream verify_fail case count changed");

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let message = decode(text(&vectors["msgs"][usize_of(&case["msg_index"])]));
        let signer_index = usize::try_from(unsigned(&case["signer_index"])).unwrap();
        let signature = fixed::<32>(text(&case["sig"]));

        let outcome =
            verify_musig2_partial_signature(&keys, &nonces, signer_index, &message, &signature);
        assert!(
            outcome.is_err(),
            "verify_fail case {case_index} ({}) was accepted",
            text(&case["comment"]),
        );
    }
}

#[test]
fn bip327_partial_signature_verify_error_vectors() {
    let vectors = parse(SIGN_VERIFY);
    let cases = array(&vectors["verify_error_test_cases"]);
    assert_eq!(cases.len(), 2, "upstream verify_error case count changed");

    for (case_index, case) in cases.iter().enumerate() {
        let contribution = text(&case["error"]["contrib"]);
        let signer = usize::try_from(unsigned(&case["error"]["signer"])).unwrap();
        let key_indices = array(&case["key_indices"]);

        if contribution == "pubkey" {
            let encoded = fixed::<33>(text(&vectors["pubkeys"][usize_of(&key_indices[signer])]));
            assert!(
                PublicKey::from_slice(&encoded).is_err(),
                "verify_error case {case_index} expected an unparsable public key",
            );
            continue;
        }

        assert_eq!(contribution, "pubnonce");
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let message = decode(text(&vectors["msgs"][usize_of(&case["msg_index"])]));
        let signer_index = usize::try_from(unsigned(&case["signer_index"])).unwrap();
        let signature = fixed::<32>(text(&case["sig"]));

        let outcome =
            verify_musig2_partial_signature(&keys, &nonces, signer_index, &message, &signature);
        assert!(
            matches!(outcome, Err(VerificationError::Crypto(reason)) if reason.contains("public nonce")),
            "verify_error case {case_index} ({}) was not refused as a nonce error: {outcome:?}",
            text(&case["comment"]),
        );
    }
}

#[test]
fn bip327_sign_error_vectors_reachable_without_a_secret_nonce() {
    // Immortal's signing API takes per-signer public nonces and aggregates
    // them itself, so the three "aggnonce" cases have no aggregate-nonce
    // parameter to corrupt. They are replayed here as per-signer nonces: the
    // same malformed bytes must be refused wherever they are offered.
    let vectors = parse(SIGN_VERIFY);
    let cases = array(&vectors["sign_error_test_cases"]);
    assert_eq!(cases.len(), 6, "upstream sign_error case count changed");

    let keys = parse_keys(&vectors["pubkeys"], &json_indices(&[0, 1]));
    let message = decode(text(&vectors["msgs"][0]));
    let mut adapted_aggnonce = 0;
    let mut refused_pubkey = 0;

    for (case_index, case) in cases.iter().enumerate() {
        if text(&case["error"]["type"]) != "invalid_contribution" {
            continue;
        }
        let contribution = text(&case["error"]["contrib"]);

        if contribution == "pubkey" {
            let signer = usize::try_from(unsigned(&case["error"]["signer"])).unwrap();
            let key_indices = array(&case["key_indices"]);
            let encoded = fixed::<33>(text(&vectors["pubkeys"][usize_of(&key_indices[signer])]));
            assert!(
                PublicKey::from_slice(&encoded).is_err(),
                "sign_error case {case_index} expected an unparsable public key",
            );
            refused_pubkey += 1;
            continue;
        }

        assert_eq!(contribution, "aggnonce");
        let malformed = fixed::<66>(text(
            &vectors["aggnonces"][usize_of(&case["aggnonce_index"])],
        ));
        let honest = fixed::<66>(text(&vectors["pnonces"][0]));
        let outcome =
            verify_musig2_partial_signature(&keys, &[malformed, honest], 0, &message, &[0_u8; 32]);
        assert!(
            matches!(outcome, Err(VerificationError::Crypto(reason)) if reason.contains("public nonce")),
            "sign_error case {case_index} ({}) accepted malformed nonce bytes: {outcome:?}",
            text(&case["comment"]),
        );
        adapted_aggnonce += 1;
    }

    assert_eq!(refused_pubkey, 1);
    assert_eq!(adapted_aggnonce, 3);
}

// --------------------------------------------------------------- SigAgg ----

#[test]
fn bip327_signature_aggregation_valid_vectors() {
    let vectors = parse(SIG_AGG);
    let cases = array(&vectors["valid_test_cases"]);
    assert_eq!(cases.len(), 4, "upstream sig_agg valid case count changed");
    let message = decode(text(&vectors["msg"]));

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let tweaks = parse_tweaks(
            &vectors["tweaks"],
            &case["tweak_indices"],
            &case["is_xonly"],
        );
        let partials: Vec<[u8; 32]> = array(&case["psig_indices"])
            .iter()
            .map(|index| fixed::<32>(text(&vectors["psigs"][usize_of(index)])))
            .collect();

        let signature =
            musig2_aggregate_partial_signatures(&keys, &nonces, &tweaks, &message, &partials)
                .unwrap_or_else(|error| {
                    panic!("sig_agg valid case {case_index} failed to aggregate: {error}")
                });
        assert_eq!(
            hex_upper(&signature),
            text(&case["expected"]),
            "sig_agg valid case {case_index} produced the wrong aggregate signature",
        );
    }
}

#[test]
fn bip327_signature_aggregation_error_vectors() {
    let vectors = parse(SIG_AGG);
    let cases = array(&vectors["error_test_cases"]);
    assert_eq!(cases.len(), 1, "upstream sig_agg error case count changed");
    let message = decode(text(&vectors["msg"]));

    for (case_index, case) in cases.iter().enumerate() {
        let keys = parse_keys(&vectors["pubkeys"], &case["key_indices"]);
        let nonces = parse_nonces(&vectors["pnonces"], &case["nonce_indices"]);
        let tweaks = parse_tweaks(
            &vectors["tweaks"],
            &case["tweak_indices"],
            &case["is_xonly"],
        );
        let partials: Vec<[u8; 32]> = array(&case["psig_indices"])
            .iter()
            .map(|index| fixed::<32>(text(&vectors["psigs"][usize_of(index)])))
            .collect();

        let outcome =
            musig2_aggregate_partial_signatures(&keys, &nonces, &tweaks, &message, &partials);
        assert!(
            matches!(outcome, Err(VerificationError::Crypto(_))),
            "sig_agg error case {case_index} ({}) aggregated an invalid partial: {outcome:?}",
            text(&case["comment"]),
        );
    }
}

// ------------------------------------------------------- DeterministicSign ----

#[test]
fn bip327_deterministic_sign_vectors_are_recorded_not_replayed() {
    // BIP-327 `DeterministicSign` is optional and is not implemented here.
    // The vectors are pinned so the gap stays reviewable and so an upstream
    // change to them is caught rather than silently absorbed.
    let vectors = parse(DET_SIGN);
    assert_eq!(array(&vectors["valid_test_cases"]).len(), 4);
    assert_eq!(array(&vectors["error_test_cases"]).len(), 5);
}

// ----------------------------------------------------------------- Helpers ----

fn parse(source: &str) -> Value {
    serde_json::from_str(source).expect("BIP-327 vector file must be valid JSON")
}

fn array(value: &Value) -> &Vec<Value> {
    value
        .as_array()
        .expect("BIP-327 vector field must be an array")
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .expect("BIP-327 vector field must be a string")
}

fn unsigned(value: &Value) -> u64 {
    value
        .as_u64()
        .expect("BIP-327 vector field must be an integer")
}

fn usize_of(value: &Value) -> usize {
    usize::try_from(unsigned(value)).expect("BIP-327 index must fit in usize")
}

fn json_indices(indices: &[u64]) -> Value {
    Value::Array(indices.iter().map(|index| Value::from(*index)).collect())
}

fn parse_keys(pubkeys: &Value, indices: &Value) -> Vec<PublicKey> {
    array(indices)
        .iter()
        .map(|index| {
            PublicKey::from_slice(&fixed::<33>(text(&pubkeys[usize_of(index)])))
                .expect("BIP-327 vector public key must parse")
        })
        .collect()
}

fn parse_nonces(pnonces: &Value, indices: &Value) -> Vec<[u8; 66]> {
    array(indices)
        .iter()
        .map(|index| fixed::<66>(text(&pnonces[usize_of(index)])))
        .collect()
}

fn parse_tweaks(tweaks: &Value, indices: &Value, is_xonly: &Value) -> Vec<Musig2Tweak> {
    let flags = array(is_xonly);
    array(indices)
        .iter()
        .zip(flags)
        .map(|(index, xonly)| Musig2Tweak {
            value: fixed::<32>(text(&tweaks[usize_of(index)])),
            xonly: xonly.as_bool().expect("is_xonly must be a boolean"),
        })
        .collect()
}

fn decode(input: &str) -> Vec<u8> {
    assert!(input.len() % 2 == 0, "hex must have even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn fixed<const N: usize>(input: &str) -> [u8; N] {
    let decoded = decode(input);
    assert_eq!(decoded.len(), N, "hex field has the wrong byte length");
    let mut output = [0_u8; N];
    output.copy_from_slice(&decoded);
    output
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("BIP-327 vector must be hexadecimal"),
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(
            char::from_digit(u32::from(byte >> 4), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
        output.push(
            char::from_digit(u32::from(byte & 0x0f), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
    }
    output
}
