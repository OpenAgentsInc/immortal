#![cfg(feature = "mkt-swp-verify")]

use immortal::mkt_swp_verify::{
    BitcoinNetwork, Timelock, Transaction, check_cltv, check_csv, musig2_aggregate_key,
    parse_bolt11, parse_swap_script, sha256, taproot_output_key, validate_timelock_ladder,
    verify_control_block, verify_musig2_partial_signature, verify_musig2_signature,
    verify_preimage,
};
use secp256k1::{PublicKey, XOnlyPublicKey};
use serde_json::Value;

#[test]
fn transaction_fixture_round_trips_and_hashes() {
    let fixture = fixture();
    let raw = decode_hex(fixture["transaction"]["raw"].as_str().unwrap());
    let transaction = Transaction::parse(&raw).unwrap();
    assert_eq!(transaction.version, 2);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.outputs[0].value_sat, 1_000);
    assert_eq!(transaction.serialize(false).unwrap(), raw);
    assert_eq!(
        encode_hex(&transaction.txid().unwrap()),
        fixture["transaction"]["txid"]
    );
    assert_eq!(transaction.txid().unwrap(), transaction.wtxid().unwrap());

    let witness_raw = decode_hex(fixture["witness_transaction"]["raw"].as_str().unwrap());
    let witness_transaction = Transaction::parse(&witness_raw).unwrap();
    assert_eq!(witness_transaction.serialize(true).unwrap(), witness_raw);
    assert_eq!(
        encode_hex(&witness_transaction.txid().unwrap()),
        fixture["witness_transaction"]["txid"]
    );
    assert_eq!(
        encode_hex(&witness_transaction.wtxid().unwrap()),
        fixture["witness_transaction"]["wtxid"]
    );
    assert!(
        Transaction::parse(&decode_hex(
            fixture["negative"]["noncanonical_transaction"]
                .as_str()
                .unwrap()
        ))
        .is_err()
    );
}

#[test]
fn script_and_taproot_vectors_are_verified() {
    assert_eq!(parse_swap_script(&[0x20; 33]).unwrap().len(), 1);
    assert!(parse_swap_script(&[0x4c, 0x02, 0x01]).is_err());

    let fixture = fixture();
    let internal_key = XOnlyPublicKey::from_byte_array(
        decode_hex(fixture["taproot"]["internal_key"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let expected_tweak = fixture["taproot"]["tweak"].as_str().unwrap();
    let mut tweak_message = internal_key.serialize().to_vec();
    assert_eq!(
        encode_hex(&immortal::mkt_swp_verify::tagged_hash(
            "TapTweak",
            &tweak_message
        )),
        expected_tweak
    );
    let (output_key, _) = taproot_output_key(internal_key, None).unwrap();
    assert_eq!(
        encode_hex(&output_key.serialize()),
        fixture["taproot"]["output_key"]
    );
    tweak_message.clear();
    assert!(verify_control_block(&output_key, &[0x51], &[0xc0]).is_err());
    assert!(parse_swap_script(&[0x6a]).is_err());

    let script_path = &fixture["taproot_script_path"];
    let script = decode_hex(script_path["script"].as_str().unwrap());
    assert_eq!(
        encode_hex(&immortal::mkt_swp_verify::tapleaf_hash(0xc0, &script).unwrap()),
        script_path["leaf_hash"]
    );
    let script_output_key = XOnlyPublicKey::from_byte_array(
        decode_hex(script_path["output_key"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
    .unwrap();
    verify_control_block(
        &script_output_key,
        &script,
        &decode_hex(script_path["control_block"].as_str().unwrap()),
    )
    .unwrap();
}

#[test]
fn bip327_key_aggregation_vector_matches() {
    let fixture = fixture();
    let keys = fixture["musig2"]["pubkeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| PublicKey::from_slice(&decode_hex(key.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let aggregate = musig2_aggregate_key(&keys).unwrap();
    assert_eq!(
        encode_hex(&aggregate.serialize()),
        fixture["musig2"]["aggregate"]
    );

    let final_vector = &fixture["schnorr_final"];
    let final_key = XOnlyPublicKey::from_byte_array(
        decode_hex(final_vector["public_key"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let signature: [u8; 64] = decode_hex(final_vector["signature"].as_str().unwrap())
        .try_into()
        .unwrap();
    verify_musig2_signature(
        &final_key,
        &decode_hex(final_vector["message"].as_str().unwrap()),
        &signature,
    )
    .unwrap();
    let mut invalid_signature = signature;
    invalid_signature[0] ^= 1;
    assert!(
        verify_musig2_signature(
            &final_key,
            &decode_hex(final_vector["message"].as_str().unwrap()),
            &invalid_signature,
        )
        .is_err()
    );

    let partial = &fixture["musig2_partial"];
    let partial_keys = partial["pubkeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| PublicKey::from_slice(&decode_hex(key.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let partial_nonces = partial["public_nonces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|nonce| decode_hex(nonce.as_str().unwrap()).try_into().unwrap())
        .collect::<Vec<[u8; 66]>>();
    let partial_signature: [u8; 32] = decode_hex(partial["partial_signature"].as_str().unwrap())
        .try_into()
        .unwrap();
    verify_musig2_partial_signature(
        &partial_keys,
        &partial_nonces,
        0,
        &decode_hex(partial["message"].as_str().unwrap()),
        &partial_signature,
    )
    .unwrap();
    let invalid_partial_signature: [u8; 32] =
        decode_hex(partial["invalid_partial_signature"].as_str().unwrap())
            .try_into()
            .unwrap();
    assert!(
        verify_musig2_partial_signature(
            &partial_keys,
            &partial_nonces,
            0,
            &decode_hex(partial["message"].as_str().unwrap()),
            &invalid_partial_signature,
        )
        .is_err()
    );
}

#[test]
fn bolt11_primary_vector_verifies_signature_and_fields() {
    let fixture = fixture();
    let invoice = parse_bolt11(fixture["bolt11"]["invoice"].as_str().unwrap()).unwrap();
    assert_eq!(invoice.network, BitcoinNetwork::Bitcoin);
    assert_eq!(invoice.amount_msat, None);
    assert_eq!(invoice.timestamp, 1_496_314_658);
    assert_eq!(
        encode_hex(&invoice.payment_hash),
        fixture["bolt11"]["payment_hash"]
    );
    assert!(
        parse_bolt11(
            fixture["negative"]["invalid_invoice_checksum"]
                .as_str()
                .unwrap()
        )
        .is_err()
    );
}

#[test]
fn preimage_and_timelock_laws_fail_closed() {
    let fixture = fixture();
    let preimage: [u8; 32] = decode_hex(fixture["preimage"]["value"].as_str().unwrap())
        .try_into()
        .unwrap();
    let payment_hash: [u8; 32] = decode_hex(fixture["preimage"]["sha256"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(sha256(&preimage), payment_hash);
    assert!(verify_preimage(&preimage, &payment_hash));
    let mut wrong_hash = payment_hash;
    wrong_hash[0] ^= 1;
    assert!(!verify_preimage(&preimage, &wrong_hash));

    assert!(
        validate_timelock_ladder(&[
            Timelock::BlockHeight(144),
            Timelock::BlockHeight(288),
            Timelock::BlockHeight(432),
        ])
        .is_ok()
    );
    assert!(
        validate_timelock_ladder(&[Timelock::BlockHeight(144), Timelock::BlockHeight(144),])
            .is_err()
    );
    assert!(check_cltv(Timelock::BlockHeight(144), 144));
    assert!(!check_cltv(Timelock::BlockHeight(145), 144));
    assert!(check_csv(144, 288));
    assert!(!check_csv(1 << 22, 144));
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipmkt/swp-verification.json")).unwrap()
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            high << 4 | low
        })
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture hex must be lowercase"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
