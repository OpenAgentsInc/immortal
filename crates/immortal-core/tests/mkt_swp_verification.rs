#![cfg(feature = "mkt-swp-verify")]

use immortal_core::mkt_swp_verify::{
    BitcoinNetwork, SwapLeafCondition, Timelock, Transaction, TransactionInput, TransactionOutput,
    assemble_taproot_claim_witness, assemble_taproot_refund_witness, check_cltv, check_csv,
    dust_threshold, is_dust, musig2_aggregate_key, parse_bolt11, parse_swap_leaf_script,
    parse_swap_script, sha256, tapbranch_hash, tapleaf_hash, taproot_key_spend_sighash,
    taproot_key_spend_signature_message, taproot_output_key, taproot_script_spend_sighash,
    taproot_script_spend_signature_message, transaction_cost, validate_taproot_claim_witness,
    validate_taproot_refund_witness, validate_timelock_ladder, validate_transaction_cost,
    verify_control_block, verify_musig2_partial_signature, verify_musig2_signature,
    verify_preimage,
};
use secp256k1::{Parity, PublicKey, XOnlyPublicKey};
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
        encode_hex(&immortal_core::mkt_swp_verify::tagged_hash(
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
        encode_hex(&immortal_core::mkt_swp_verify::tapleaf_hash(0xc0, &script).unwrap()),
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

#[test]
fn taproot_script_path_construction_matches_pinned_vectors() {
    let preimage: [u8; 32] = (0_u8..32).collect::<Vec<_>>().try_into().unwrap();
    let payment_hash = sha256(&preimage);
    let claim_key: [u8; 32] =
        decode_hex("d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8")
            .try_into()
            .unwrap();
    let refund_key: [u8; 32] =
        decode_hex("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27")
            .try_into()
            .unwrap();
    let internal_key = XOnlyPublicKey::from_byte_array(
        decode_hex("e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f")
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut claim_script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    claim_script.extend_from_slice(&payment_hash);
    claim_script.extend_from_slice(&[0x88, 0x20]);
    claim_script.extend_from_slice(&claim_key);
    claim_script.push(0xac);
    let mut refund_script = vec![0x02, 0x90, 0x00, 0xb1, 0x75, 0x20];
    refund_script.extend_from_slice(&refund_key);
    refund_script.push(0xac);
    let claim_hash = tapleaf_hash(0xc0, &claim_script).unwrap();
    let refund_hash = tapleaf_hash(0xc0, &refund_script).unwrap();
    let root = tapbranch_hash(claim_hash, refund_hash);
    let (output_key, parity) = taproot_output_key(internal_key, Some(root)).unwrap();
    let mut claim_control = vec![0xc0 | u8::from(parity == Parity::Odd)];
    claim_control.extend_from_slice(&internal_key.serialize());
    claim_control.extend_from_slice(&refund_hash);
    let mut refund_control = vec![0xc0 | u8::from(parity == Parity::Odd)];
    refund_control.extend_from_slice(&internal_key.serialize());
    refund_control.extend_from_slice(&claim_hash);
    let mut prevout_script = vec![0x51, 0x20];
    prevout_script.extend_from_slice(&output_key.serialize());
    let destination =
        decode_hex("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
    let prevouts = vec![TransactionOutput {
        value_sat: 100_000,
        script_pubkey: prevout_script,
    }];
    let mut transaction = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid: [0x22; 32],
            previous_output: 1,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: 99_000,
            script_pubkey: destination,
        }],
        144,
    );
    let sighash =
        taproot_script_spend_sighash(&transaction, &prevouts, 0, &refund_script, &refund_control)
            .unwrap();
    let claim_sighash =
        taproot_script_spend_sighash(&transaction, &prevouts, 0, &claim_script, &claim_control)
            .unwrap();
    transaction
        .set_input_witness(
            0,
            assemble_taproot_refund_witness([0x11; 64], &refund_script, &refund_control).unwrap(),
        )
        .unwrap();
    let fixture = fixture();
    let vector = &fixture["taproot_script_spend"];
    assert_eq!(
        encode_hex(&transaction.inputs[0].serialize_without_witness().unwrap()),
        vector["transaction"]["serialized_input"]
    );
    assert_eq!(
        encode_hex(&transaction.outputs[0].serialize().unwrap()),
        vector["transaction"]["serialized_output"]
    );
    assert_eq!(encode_hex(&claim_script), vector["claim_script"]);
    assert_eq!(encode_hex(&refund_script), vector["refund_script"]);
    assert_eq!(encode_hex(&claim_hash), vector["claim_leaf_hash"]);
    assert_eq!(encode_hex(&refund_hash), vector["refund_leaf_hash"]);
    assert_eq!(encode_hex(&root), vector["merkle_root"]);
    assert_eq!(encode_hex(&output_key.serialize()), vector["output_key"]);
    assert_eq!(encode_hex(&claim_control), vector["claim_control_block"]);
    assert_eq!(encode_hex(&refund_control), vector["refund_control_block"]);
    assert_eq!(
        encode_hex(
            &taproot_script_spend_signature_message(
                &transaction,
                &prevouts,
                0,
                &refund_script,
                &refund_control,
            )
            .unwrap()
        ),
        vector["transaction"]["refund_signature_message"]
    );
    assert_eq!(
        encode_hex(&sighash),
        vector["transaction"]["refund_sighash"]
    );
    assert_eq!(
        encode_hex(&claim_sighash),
        vector["transaction"]["claim_sighash"]
    );
    assert_eq!(
        encode_hex(&transaction.serialize(true).unwrap()),
        vector["transaction"]["refund_signed_raw"]
    );
    assert_eq!(
        encode_hex(&transaction.txid().unwrap()),
        vector["transaction"]["txid"]
    );
    assert_eq!(
        encode_hex(&transaction.wtxid().unwrap()),
        vector["transaction"]["wtxid"]
    );
    assert_eq!(transaction.weight().unwrap(), 550);
    assert_eq!(transaction.virtual_size().unwrap(), 138);
    assert_eq!(
        parse_swap_leaf_script(&claim_script).unwrap().condition,
        SwapLeafCondition::Hashlock(payment_hash)
    );
    assert_eq!(
        parse_swap_leaf_script(&refund_script).unwrap().condition,
        SwapLeafCondition::Cltv(144)
    );
    let validated = validate_taproot_refund_witness(
        &transaction,
        &prevouts,
        0,
        &refund_script,
        &refund_control,
    )
    .unwrap();
    assert_eq!(validated.signature, [0x11; 64]);
    assert_eq!(validated.sighash, sighash);
    let cost = transaction_cost(&transaction, &prevouts).unwrap();
    assert_eq!(cost.fee_sat, 1_000);
    assert_eq!(cost.weight, 550);
    assert_eq!(cost.virtual_size, 138);
    assert_eq!(
        validate_transaction_cost(&transaction, &prevouts, 1_000, 8).unwrap(),
        cost
    );
    assert_eq!(
        dust_threshold(&prevouts[0].script_pubkey, 3_000).unwrap(),
        330
    );
    assert!(
        is_dust(
            &TransactionOutput {
                value_sat: 329,
                script_pubkey: prevouts[0].script_pubkey.clone(),
            },
            3_000,
        )
        .unwrap()
    );
    assert!(
        !is_dust(
            &TransactionOutput {
                value_sat: 330,
                script_pubkey: prevouts[0].script_pubkey.clone(),
            },
            3_000,
        )
        .unwrap()
    );

    let mut claim_transaction = Transaction::new(
        transaction.version,
        transaction.inputs.clone(),
        transaction.outputs.clone(),
        transaction.lock_time,
    );
    claim_transaction
        .set_input_witness(
            0,
            assemble_taproot_claim_witness([0x11; 64], preimage, &claim_script, &claim_control)
                .unwrap(),
        )
        .unwrap();
    let validated = validate_taproot_claim_witness(
        &claim_transaction,
        &prevouts,
        0,
        &claim_script,
        &claim_control,
    )
    .unwrap();
    assert_eq!(validated.signature, [0x11; 64]);
    assert_eq!(validated.sighash, claim_sighash);
}

#[test]
fn taproot_key_path_default_sighash_matches_bip341() {
    let fixture = fixture();
    let vector = &fixture["taproot_key_spend"];
    let transaction =
        Transaction::parse(&decode_hex(vector["raw_unsigned_tx"].as_str().unwrap())).unwrap();
    let prevouts = vector["prevouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|prevout| TransactionOutput {
            value_sat: prevout["value_sat"].as_u64().unwrap(),
            script_pubkey: decode_hex(prevout["script_pubkey"].as_str().unwrap()),
        })
        .collect::<Vec<_>>();
    let input_index = usize::try_from(vector["input_index"].as_u64().unwrap()).unwrap();
    assert_eq!(
        encode_hex(
            &taproot_key_spend_signature_message(&transaction, &prevouts, input_index).unwrap()
        ),
        vector["signature_message"]
    );
    assert_eq!(
        encode_hex(&taproot_key_spend_sighash(&transaction, &prevouts, input_index).unwrap()),
        vector["sighash"]
    );

    let mut changed_amounts = prevouts.clone();
    changed_amounts[input_index].value_sat += 1;
    assert_ne!(
        taproot_key_spend_sighash(&transaction, &changed_amounts, input_index).unwrap(),
        taproot_key_spend_sighash(&transaction, &prevouts, input_index).unwrap()
    );
    let mut wrong_selected_script = prevouts.clone();
    wrong_selected_script[input_index].script_pubkey[0] = 0x00;
    assert!(taproot_key_spend_sighash(&transaction, &wrong_selected_script, input_index).is_err());
    assert!(taproot_key_spend_sighash(&transaction, &prevouts, transaction.inputs.len()).is_err());
}

#[test]
fn taproot_script_path_mutations_fail_closed() {
    let fixture = fixture();
    let vector = &fixture["taproot_script_spend"];
    let transaction_vector = &vector["transaction"];
    let mut transaction = Transaction::parse(&decode_hex(
        transaction_vector["refund_signed_raw"].as_str().unwrap(),
    ))
    .unwrap();
    let prevouts = vec![TransactionOutput {
        value_sat: vector["prevout"]["value_sat"].as_u64().unwrap(),
        script_pubkey: decode_hex(vector["prevout"]["script_pubkey"].as_str().unwrap()),
    }];
    let refund_script = decode_hex(vector["refund_script"].as_str().unwrap());
    let refund_control = decode_hex(vector["refund_control_block"].as_str().unwrap());
    let claim_script = decode_hex(vector["claim_script"].as_str().unwrap());
    let claim_control = decode_hex(vector["claim_control_block"].as_str().unwrap());
    let expected =
        taproot_script_spend_sighash(&transaction, &prevouts, 0, &refund_script, &refund_control)
            .unwrap();

    let mut wrong_prevout = transaction.clone();
    wrong_prevout.inputs[0].previous_txid[0] ^= 1;
    assert_ne!(
        taproot_script_spend_sighash(
            &wrong_prevout,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .unwrap(),
        expected
    );
    let mut wrong_amount = prevouts.clone();
    wrong_amount[0].value_sat += 1;
    assert_ne!(
        taproot_script_spend_sighash(
            &transaction,
            &wrong_amount,
            0,
            &refund_script,
            &refund_control,
        )
        .unwrap(),
        expected
    );
    let mut wrong_leaf = refund_script.clone();
    wrong_leaf[1] ^= 1;
    assert!(
        taproot_script_spend_sighash(&transaction, &prevouts, 0, &wrong_leaf, &refund_control,)
            .is_err()
    );
    let mut wrong_control = refund_control.clone();
    let last = wrong_control.len() - 1;
    wrong_control[last] ^= 1;
    assert!(
        taproot_script_spend_sighash(&transaction, &prevouts, 0, &refund_script, &wrong_control,)
            .is_err()
    );

    let mut wrong_sequence = transaction.clone();
    wrong_sequence.inputs[0].sequence -= 1;
    assert_ne!(
        taproot_script_spend_sighash(
            &wrong_sequence,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .unwrap(),
        expected
    );
    let mut wrong_lock_time = transaction.clone();
    wrong_lock_time.lock_time -= 1;
    assert_ne!(
        taproot_script_spend_sighash(
            &wrong_lock_time,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .unwrap(),
        expected
    );
    assert!(
        validate_taproot_refund_witness(
            &wrong_lock_time,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .is_err()
    );

    let mut explicit_sighash_witness = transaction.inputs[0].witness.clone();
    explicit_sighash_witness[0].push(0);
    transaction
        .set_input_witness(0, explicit_sighash_witness)
        .unwrap();
    assert!(
        validate_taproot_refund_witness(
            &transaction,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .is_err()
    );
    transaction
        .set_input_witness(0, vec![vec![0x11; 64], refund_script.clone()])
        .unwrap();
    assert!(
        validate_taproot_refund_witness(
            &transaction,
            &prevouts,
            0,
            &refund_script,
            &refund_control,
        )
        .is_err()
    );

    let mut wrong_preimage: [u8; 32] = decode_hex(vector["preimage"].as_str().unwrap())
        .try_into()
        .unwrap();
    wrong_preimage[0] ^= 1;
    assert!(
        assemble_taproot_claim_witness([0x11; 64], wrong_preimage, &claim_script, &claim_control,)
            .is_err()
    );
    assert!(validate_transaction_cost(&transaction, &prevouts, 999, 8).is_err());
    let mut excessive_output = transaction.clone();
    excessive_output.outputs[0].value_sat = prevouts[0].value_sat + 1;
    assert!(transaction_cost(&excessive_output, &prevouts).is_err());
    assert!(
        taproot_script_spend_sighash(&transaction, &[], 0, &refund_script, &refund_control,)
            .is_err()
    );
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-verification.json"
    ))
    .unwrap()
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
