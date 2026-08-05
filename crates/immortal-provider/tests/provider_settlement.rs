#![cfg(all(feature = "funded", unix))]

use immortal_core::mkt_swp_verify::{
    Transaction, TransactionOutput, VerificationError, musig2_aggregate_key, musig2_taproot_tweak,
    musig2_tweaked_aggregate_key, sha256, tapbranch_hash, tapleaf_hash, taproot_output_key,
    taproot_script_spend_sighash, taproot_script_spend_signature_message,
};
use immortal_provider::{
    settlement::{
        ClaimPreimage, CooperativeSettlementTemplate, SettlementBridge, SettlementError,
        SettlementTemplate, SignedSettlementTransaction,
    },
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
};
use secp256k1::{Parity, PublicKey, XOnlyPublicKey};
use serde_json::Value;
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
const SETTLEMENT_CONSTRUCTION_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/settlement-construction-v1.json");
const SWP_VERIFICATION_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/nipmkt/swp-verification.json");

struct SettlementFixture {
    wallet: ProviderWallet,
    claim: SettlementTemplate,
    refund: SettlementTemplate,
    claim_preimage: [u8; 32],
    document: Value,
}

#[test]
fn claim_and_refund_match_the_committed_construction_vector() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);
    let claim = bridge.claim(&fixture.claim, ClaimPreimage::new(fixture.claim_preimage))?;
    let refund = bridge.refund(&fixture.refund)?;
    assert_transaction_vector(
        &fixture.claim,
        &claim,
        fixture_value(&fixture.document, &["expected", "claim"])
            .ok_or("settlement fixture has no claim expectation")?,
    )?;
    assert_transaction_vector(
        &fixture.refund,
        &refund,
        fixture_value(&fixture.document, &["expected", "refund"])
            .ok_or("settlement fixture has no refund expectation")?,
    )?;
    Ok(())
}

#[test]
fn claim_and_refund_are_validated_before_broadcast() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);

    let claim = bridge.claim(&fixture.claim, ClaimPreimage::new(fixture.claim_preimage))?;
    let claim_transaction = Transaction::parse(claim.broadcast_bytes())?;
    assert_eq!(claim_transaction.txid()?, claim.transaction_id());
    assert_eq!(claim_transaction.wtxid()?, claim.witness_transaction_id());
    assert_eq!(claim.cost().fee_sat, 1_000);
    assert!(claim.cost().weight <= fixture.claim.maximum_weight);
    assert!(format!("{claim:?}").contains("raw_transaction: \"[REDACTED]\""));

    let refund = bridge.refund(&fixture.refund)?;
    let refund_transaction_id = refund.transaction_id();
    let refund_witness_transaction_id = refund.witness_transaction_id();
    assert_eq!(refund.cost().fee_sat, 1_000);
    assert!(refund.cost().weight <= fixture.refund.maximum_weight);
    let refund_bytes = refund.into_broadcast_bytes();
    let refund_transaction = Transaction::parse(&refund_bytes)?;
    assert_eq!(refund_transaction.txid()?, refund_transaction_id);
    assert_eq!(refund_transaction.wtxid()?, refund_witness_transaction_id);
    Ok(())
}

#[test]
fn wrong_path_and_wallet_key_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);

    assert!(matches!(
        bridge.claim(&fixture.refund, ClaimPreimage::new(fixture.claim_preimage)),
        Err(SettlementError::WrongPath)
    ));
    assert!(matches!(
        bridge.refund(&fixture.claim),
        Err(SettlementError::WrongPath)
    ));

    let mut wrong_key = fixture.claim.clone();
    wrong_key.wallet_path = WalletPath::new(0, false, 19)?;
    assert!(matches!(
        bridge.claim(&wrong_key, ClaimPreimage::new(fixture.claim_preimage)),
        Err(SettlementError::SigningKeyMismatch)
    ));
    Ok(())
}

#[test]
fn claim_preimage_is_redacted_and_must_match() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);
    let preimage = ClaimPreimage::new([41; 32]);
    assert_eq!(format!("{preimage:?}"), "ClaimPreimage([REDACTED])");

    let result = bridge.claim(&fixture.claim, preimage);
    assert!(matches!(result, Err(SettlementError::PreimageMismatch)));
    let error = result.err().ok_or("missing preimage mismatch")?;
    assert_eq!(
        error.to_string(),
        "claim material does not match the settlement hashlock"
    );
    Ok(())
}

#[test]
fn refund_timelock_and_control_block_are_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);

    let mut early = fixture.refund.clone();
    early.lock_time = 143;
    assert!(matches!(
        bridge.refund(&early),
        Err(SettlementError::Core(VerificationError::Invalid(
            "refund CLTV is not satisfied"
        )))
    ));

    let mut wrong_control_block = fixture.refund.clone();
    let sibling = wrong_control_block
        .taproot_control_block
        .get_mut(33)
        .ok_or("missing Taproot sibling")?;
    *sibling ^= 1;
    assert!(matches!(
        bridge.refund(&wrong_control_block),
        Err(SettlementError::Core(VerificationError::Invalid(
            "taproot control block commitment"
        )))
    ));
    Ok(())
}

#[test]
fn fee_dust_and_weight_policies_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);

    let mut excessive_fee = fixture.refund.clone();
    excessive_fee.maximum_fee_sat = 999;
    assert!(matches!(
        bridge.refund(&excessive_fee),
        Err(SettlementError::Core(VerificationError::Invalid(
            "transaction fee exceeds policy"
        )))
    ));

    let mut dust = fixture.refund.clone();
    dust.destination_value_sat = 329;
    assert!(matches!(
        bridge.refund(&dust),
        Err(SettlementError::DustOutput)
    ));

    let mut excessive_weight = fixture.refund.clone();
    excessive_weight.maximum_weight = 1;
    assert!(matches!(
        bridge.refund(&excessive_weight),
        Err(SettlementError::WeightLimit)
    ));
    Ok(())
}

#[test]
fn cooperative_key_path_is_smaller_and_abort_keeps_script_exit_usable() -> Result<(), Box<dyn Error>>
{
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);
    let requester_path = fixture.claim.wallet_path;
    let provider_unilateral_path = WalletPath::new(1, false, 7)?;
    let provider_cooperative_path = WalletPath::new(1, false, 8)?;
    let participant_keys = [
        compressed_even(fixture.wallet.derive_address(requester_path)?.internal_key),
        compressed_even(
            fixture
                .wallet
                .derive_address(provider_cooperative_path)?
                .internal_key,
        ),
    ];
    let keys = participant_keys
        .iter()
        .map(|key| PublicKey::from_slice(key))
        .collect::<Result<Vec<_>, _>>()?;
    let requester_script = claim_script(
        fixture.claim_preimage,
        fixture.wallet.derive_address(requester_path)?.internal_key,
    );
    let provider_script = claim_script(
        fixture.claim_preimage,
        fixture
            .wallet
            .derive_address(provider_unilateral_path)?
            .internal_key,
    );
    let requester_leaf = tapleaf_hash(0xc0, &requester_script)?;
    let provider_leaf = tapleaf_hash(0xc0, &provider_script)?;
    let merkle_root = tapbranch_hash(requester_leaf, provider_leaf);
    let internal_key = musig2_aggregate_key(&keys)?;
    let (output_key, output_parity) = taproot_output_key(internal_key, Some(merkle_root))?;
    let tweak = musig2_taproot_tweak(&keys, merkle_root)?;
    let aggregate_key = musig2_tweaked_aggregate_key(&keys, &[tweak])?;
    assert_eq!(aggregate_key, output_key);
    let requester_control_block = control_block(output_parity, internal_key, provider_leaf);
    let provider_control_block = control_block(output_parity, internal_key, requester_leaf);
    let mut settlement = fixture.claim.clone();
    settlement.maximum_fee_rate_sat_per_vbyte = 20;
    settlement.prevout_script_pubkey =
        [&[0x51, 0x20][..], aggregate_key.serialize().as_slice()].concat();
    settlement.taproot_script = requester_script;
    settlement.taproot_control_block = requester_control_block;
    let common = CooperativeSettlementTemplate {
        settlement,
        cooperative_wallet_path: requester_path,
        participant_keys,
        provider_index: 0,
        taproot_merkle_root: merkle_root,
        transcript_digest: [42; 32],
        latest_safe_height: 200,
    };
    let mut requester_round = bridge.begin_cooperative(&common, 150)?;
    let mut provider_template = common.clone();
    provider_template.settlement.wallet_path = provider_unilateral_path;
    provider_template.cooperative_wallet_path = provider_cooperative_path;
    provider_template.settlement.taproot_script = provider_script;
    provider_template.settlement.taproot_control_block = provider_control_block;
    provider_template.provider_index = 1;
    let mut provider_round = bridge.begin_cooperative(&provider_template, 150)?;
    let requester_commitment = requester_round.nonce_commitment();
    let provider_commitment = provider_round.nonce_commitment();
    requester_round.register_counterparty_nonce_commitment(provider_commitment, 150)?;
    provider_round.register_counterparty_nonce_commitment(requester_commitment, 150)?;
    let public_nonces = [
        requester_round.reveal_public_nonce(150)?,
        provider_round.reveal_public_nonce(150)?,
    ];
    let requester_partial =
        bridge.sign_cooperative_partial(&mut requester_round, 150, &public_nonces)?;
    let provider_partial =
        bridge.sign_cooperative_partial(&mut provider_round, 150, &public_nonces)?;
    let cooperative = bridge.finalize_cooperative(
        requester_round,
        150,
        &public_nonces,
        &[requester_partial, provider_partial],
    )?;
    let unilateral = bridge.claim(
        &common.settlement,
        ClaimPreimage::new(fixture.claim_preimage),
    )?;
    assert_eq!(cooperative.cost().virtual_size, 111);
    assert_eq!(unilateral.cost().virtual_size, 155);
    let cooperative_transaction = Transaction::parse(cooperative.broadcast_bytes())?;
    let unilateral_transaction = Transaction::parse(unilateral.broadcast_bytes())?;
    assert_eq!(
        cooperative_transaction
            .inputs
            .first()
            .ok_or("cooperative transaction has no input")?
            .witness
            .len(),
        1
    );
    assert_eq!(
        cooperative_transaction.inputs[0].previous_txid,
        unilateral_transaction.inputs[0].previous_txid
    );
    assert_eq!(
        cooperative_transaction.inputs[0].previous_output,
        unilateral_transaction.inputs[0].previous_output
    );

    let mut aborted_round = bridge.begin_cooperative(&common, 150)?;
    aborted_round.abort();
    assert!(aborted_round.is_terminal());
    assert!(matches!(
        aborted_round.reveal_public_nonce(150),
        Err(SettlementError::CooperativeState)
    ));
    let fallback = bridge.claim(
        &common.settlement,
        ClaimPreimage::new(fixture.claim_preimage),
    )?;
    assert_eq!(fallback.cost(), unilateral.cost());
    Ok(())
}

#[test]
fn cooperative_round_enforces_exit_commitment_and_height_gates() -> Result<(), Box<dyn Error>> {
    let fixture = settlement_fixture()?;
    let bridge = SettlementBridge::new(&fixture.wallet);
    let requester_path = fixture.claim.wallet_path;
    let provider_path = WalletPath::new(1, false, 7)?;
    let participant_keys = [
        compressed_even(fixture.wallet.derive_address(requester_path)?.internal_key),
        compressed_even(fixture.wallet.derive_address(provider_path)?.internal_key),
    ];
    let keys = participant_keys
        .iter()
        .map(|key| PublicKey::from_slice(key))
        .collect::<Result<Vec<_>, _>>()?;
    let requester_script = claim_script(
        fixture.claim_preimage,
        fixture.wallet.derive_address(requester_path)?.internal_key,
    );
    let provider_script = claim_script(
        fixture.claim_preimage,
        fixture.wallet.derive_address(provider_path)?.internal_key,
    );
    let requester_leaf = tapleaf_hash(0xc0, &requester_script)?;
    let provider_leaf = tapleaf_hash(0xc0, &provider_script)?;
    let merkle_root = tapbranch_hash(requester_leaf, provider_leaf);
    let internal_key = musig2_aggregate_key(&keys)?;
    let (output_key, output_parity) = taproot_output_key(internal_key, Some(merkle_root))?;
    let mut settlement = fixture.claim.clone();
    settlement.maximum_fee_rate_sat_per_vbyte = 20;
    settlement.prevout_script_pubkey =
        [&[0x51, 0x20][..], output_key.serialize().as_slice()].concat();
    settlement.taproot_script = requester_script;
    settlement.taproot_control_block = control_block(output_parity, internal_key, provider_leaf);
    let template = CooperativeSettlementTemplate {
        settlement,
        cooperative_wallet_path: requester_path,
        participant_keys,
        provider_index: 0,
        taproot_merkle_root: merkle_root,
        transcript_digest: [43; 32],
        latest_safe_height: 200,
    };

    let mut wrong_exit = template.clone();
    wrong_exit.settlement.taproot_control_block[33] ^= 1;
    assert!(matches!(
        bridge.begin_cooperative(&wrong_exit, 150),
        Err(SettlementError::Core(VerificationError::Invalid(
            "taproot control block commitment"
        )))
    ));

    let mut round = bridge.begin_cooperative(&template, 150)?;
    assert!(matches!(
        round.reveal_public_nonce(150),
        Err(SettlementError::CooperativeState)
    ));
    let commitment = sha256(&[7; 66]);
    round.register_counterparty_nonce_commitment(commitment, 150)?;
    assert!(matches!(
        round.register_counterparty_nonce_commitment([9; 32], 150),
        Err(SettlementError::NonceCommitmentMismatch)
    ));
    assert!(matches!(
        round.reveal_public_nonce(201),
        Err(SettlementError::CooperativeExpired)
    ));
    assert!(round.is_terminal());
    assert!(matches!(
        bridge.begin_cooperative(&template, 201),
        Err(SettlementError::CooperativeExpired)
    ));
    Ok(())
}

fn settlement_fixture() -> Result<SettlementFixture, Box<dyn Error>> {
    let document: Value = serde_json::from_slice(SETTLEMENT_CONSTRUCTION_FIXTURE)?;
    validate_fixture_provenance(&document)?;
    let wallet_key_material =
        fixture_string(&document, &["synthetic_vectors", "wallet_key_material_hex"])?;
    let claim_preimage = decode_lower_hex_32(fixture_string(
        &document,
        &["synthetic_vectors", "claim_preimage_hex"],
    )?)?;
    let payment_hash = sha256(&claim_preimage);
    assert_fixture_hex(
        &document,
        &["synthetic_vectors", "payment_hash"],
        &payment_hash,
    )?;

    if fixture_string(&document, &["derivation", "network"])? != "regtest" {
        return Err("settlement fixture must use regtest".into());
    }
    let wallet = load_wallet(wallet_key_material)?;
    let settlement_path = fixture_wallet_path(&document, "settlement_path")?;
    let signing_key = wallet.derive_address(settlement_path)?.internal_key;
    assert_fixture_hex(&document, &["derivation", "signing_key"], &signing_key)?;

    let mut claim_script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    claim_script.extend_from_slice(&payment_hash);
    claim_script.extend_from_slice(&[0x88, 0x20]);
    claim_script.extend_from_slice(&signing_key);
    claim_script.push(0xac);
    assert_fixture_hex(&document, &["swap_tree", "claim_script"], &claim_script)?;

    let mut refund_script = vec![0x02, 0x90, 0x00, 0xb1, 0x75, 0x20];
    refund_script.extend_from_slice(&signing_key);
    refund_script.push(0xac);
    assert_fixture_hex(&document, &["swap_tree", "refund_script"], &refund_script)?;

    let claim_leaf = tapleaf_hash(0xc0, &claim_script)?;
    let refund_leaf = tapleaf_hash(0xc0, &refund_script)?;
    let merkle_root = tapbranch_hash(claim_leaf, refund_leaf);
    assert_fixture_hex(&document, &["swap_tree", "claim_leaf_hash"], &claim_leaf)?;
    assert_fixture_hex(&document, &["swap_tree", "refund_leaf_hash"], &refund_leaf)?;
    assert_fixture_hex(&document, &["swap_tree", "merkle_root"], &merkle_root)?;
    let tree_path = fixture_wallet_path(&document, "tree_path")?;
    let tree_key = XOnlyPublicKey::from_byte_array(wallet.derive_address(tree_path)?.internal_key)?;
    assert_fixture_hex(
        &document,
        &["derivation", "tree_internal_key"],
        &tree_key.serialize(),
    )?;
    let (output_key, parity) = taproot_output_key(tree_key, Some(merkle_root))?;
    assert_fixture_hex(
        &document,
        &["swap_tree", "output_key"],
        &output_key.serialize(),
    )?;

    let mut claim_control_block = vec![0xc0 | u8::from(parity == Parity::Odd)];
    claim_control_block.extend_from_slice(&tree_key.serialize());
    claim_control_block.extend_from_slice(&refund_leaf);
    let mut refund_control_block = vec![0xc0 | u8::from(parity == Parity::Odd)];
    refund_control_block.extend_from_slice(&tree_key.serialize());
    refund_control_block.extend_from_slice(&claim_leaf);
    assert_fixture_hex(
        &document,
        &["swap_tree", "claim_control_block"],
        &claim_control_block,
    )?;
    assert_fixture_hex(
        &document,
        &["swap_tree", "refund_control_block"],
        &refund_control_block,
    )?;

    let mut prevout_script_pubkey = vec![0x51, 0x20];
    prevout_script_pubkey.extend_from_slice(&output_key.serialize());
    assert_fixture_hex(
        &document,
        &["swap_tree", "prevout_script_pubkey"],
        &prevout_script_pubkey,
    )?;
    let destination_script_pubkey = wallet
        .derive_address(fixture_wallet_path(&document, "destination_path")?)?
        .script_pubkey
        .to_vec();
    assert_fixture_hex(
        &document,
        &["derivation", "destination_script_pubkey"],
        &destination_script_pubkey,
    )?;

    let base = SettlementTemplate {
        wallet_path: settlement_path,
        previous_txid_wire: decode_lower_hex_32(fixture_string(
            &document,
            &["transaction", "previous_txid_wire"],
        )?)?,
        previous_output: u32::try_from(fixture_u64(
            &document,
            &["transaction", "previous_output"],
        )?)?,
        prevout_value_sat: fixture_u64(&document, &["transaction", "prevout_value_sat"])?,
        prevout_script_pubkey,
        destination_value_sat: fixture_u64(&document, &["transaction", "destination_value_sat"])?,
        destination_script_pubkey,
        transaction_version: i32::try_from(fixture_u64(&document, &["transaction", "version"])?)?,
        input_sequence: u32::try_from(fixture_u64(&document, &["transaction", "sequence"])?)?,
        lock_time: u32::try_from(fixture_u64(&document, &["transaction", "lock_time"])?)?,
        taproot_script: Vec::new(),
        taproot_control_block: Vec::new(),
        maximum_fee_sat: fixture_u64(&document, &["transaction", "maximum_fee_sat"])?,
        maximum_fee_rate_sat_per_vbyte: fixture_u64(
            &document,
            &["transaction", "maximum_fee_rate_sat_per_vbyte"],
        )?,
        maximum_weight: fixture_u64(&document, &["transaction", "maximum_weight"])?,
        dust_relay_fee_sat_per_kilobyte: fixture_u64(
            &document,
            &["transaction", "dust_relay_fee_sat_per_kilobyte"],
        )?,
    };

    let mut claim = base.clone();
    claim.taproot_script = claim_script;
    claim.taproot_control_block = claim_control_block;
    let mut refund = base;
    refund.taproot_script = refund_script;
    refund.taproot_control_block = refund_control_block;
    Ok(SettlementFixture {
        wallet,
        claim,
        refund,
        claim_preimage,
        document,
    })
}

fn load_wallet(encoded_key_material: &str) -> Result<ProviderWallet, Box<dyn Error>> {
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = temporary_seed_path(sequence);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&path)?;
    file.write_all(encoded_key_material.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let wallet = ProviderWallet::load(&path, BitcoinNetwork::Regtest)?;
    fs::remove_file(path)?;
    Ok(wallet)
}

fn compressed_even(key: [u8; 32]) -> [u8; 33] {
    let mut compressed = [0_u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&key);
    compressed
}

fn claim_script(preimage: [u8; 32], signing_key: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    script.extend_from_slice(&sha256(&preimage));
    script.extend_from_slice(&[0x88, 0x20]);
    script.extend_from_slice(&signing_key);
    script.push(0xac);
    script
}

fn control_block(
    output_parity: Parity,
    internal_key: XOnlyPublicKey,
    sibling: [u8; 32],
) -> Vec<u8> {
    let parity = if output_parity == Parity::Odd { 1 } else { 0 };
    let mut control = Vec::with_capacity(65);
    control.push(0xc0 | parity);
    control.extend_from_slice(&internal_key.serialize());
    control.extend_from_slice(&sibling);
    control
}

fn validate_fixture_provenance(document: &Value) -> Result<(), Box<dyn Error>> {
    if fixture_string(document, &["schema"])?
        != "openagents.immortal.provider-settlement-construction.v1"
        || fixture_string(document, &["classification"])?
            != "synthetic_public_protocol_test_vector_not_operator_custody_material"
    {
        return Err("settlement construction fixture identity is invalid".into());
    }
    if !fixture_string(document, &["sources", "bip341"])?
        .contains("e35a46ecf3031c21dc7f7fdb694986789a3a8144")
        || !fixture_string(document, &["sources", "bip342"])?
            .contains("24e96e870fffaa257b465ce1f0370c14aac588e8")
    {
        return Err("settlement construction fixture does not pin BIP-341/342".into());
    }

    let source: Value = serde_json::from_slice(SWP_VERIFICATION_FIXTURE)?;
    for (provider_path, source_path) in [
        (
            &["synthetic_vectors", "claim_preimage_hex"][..],
            &["taproot_script_spend", "preimage"][..],
        ),
        (
            &["synthetic_vectors", "payment_hash"][..],
            &["taproot_script_spend", "payment_hash"][..],
        ),
        (
            &["sources", "bolt11", "payment_hash"][..],
            &["bolt11", "payment_hash"][..],
        ),
    ] {
        if fixture_string(document, provider_path)? != fixture_string(&source, source_path)? {
            return Err("settlement fixture source binding changed".into());
        }
    }
    let invoice = fixture_string(&source, &["bolt11", "invoice"])?;
    assert_fixture_hex(
        document,
        &["sources", "bolt11", "invoice_sha256"],
        &sha256(invoice.as_bytes()),
    )?;
    if fixture_string(document, &["sources", "bolt11", "scope"])?
        != "invoice_parsing_reference_only_settlement_construction_binds_the_separate_synthetic_preimage_pair"
    {
        return Err("settlement fixture overstates its BOLT11 binding".into());
    }
    Ok(())
}

fn assert_transaction_vector(
    template: &SettlementTemplate,
    signed: &SignedSettlementTransaction,
    expected: &Value,
) -> Result<(), Box<dyn Error>> {
    let transaction = Transaction::parse(signed.broadcast_bytes())?;
    let prevouts = vec![TransactionOutput {
        value_sat: template.prevout_value_sat,
        script_pubkey: template.prevout_script_pubkey.clone(),
    }];
    let signature_message = taproot_script_spend_signature_message(
        &transaction,
        &prevouts,
        0,
        &template.taproot_script,
        &template.taproot_control_block,
    )?;
    let sighash = taproot_script_spend_sighash(
        &transaction,
        &prevouts,
        0,
        &template.taproot_script,
        &template.taproot_control_block,
    )?;
    let witness = transaction
        .inputs
        .first()
        .ok_or("settlement vector transaction has no input")?
        .witness
        .iter()
        .map(|item| lower_hex(item))
        .collect::<Vec<_>>();
    let expected_witness = fixture_value(expected, &["witness"])
        .and_then(Value::as_array)
        .ok_or("settlement vector has no expected witness")?;
    if witness.len() != expected_witness.len()
        || witness
            .iter()
            .zip(expected_witness)
            .any(|(actual, expected)| expected.as_str() != Some(actual))
    {
        return Err("settlement witness differs from the committed vector".into());
    }
    let signature = witness
        .first()
        .ok_or("settlement vector witness has no signature")?;

    for (field, actual) in [
        (
            "unsigned_transaction",
            lower_hex(&transaction.serialize(false)?),
        ),
        ("signature_message", lower_hex(&signature_message)),
        ("sighash", lower_hex(&sighash)),
        ("signature", signature.clone()),
        ("signed_raw", lower_hex(signed.broadcast_bytes())),
        ("txid", lower_hex(&signed.transaction_id())),
        ("wtxid", lower_hex(&signed.witness_transaction_id())),
    ] {
        if fixture_string(expected, &[field])? != actual {
            return Err(format!("settlement {field} differs from the committed vector").into());
        }
    }
    for (field, actual) in [
        ("fee_sat", signed.cost().fee_sat),
        ("weight", signed.cost().weight),
        ("virtual_size", signed.cost().virtual_size),
    ] {
        if fixture_u64(expected, &[field])? != actual {
            return Err(format!("settlement {field} differs from the committed vector").into());
        }
    }
    if transaction.txid()? != signed.transaction_id()
        || transaction.wtxid()? != signed.witness_transaction_id()
    {
        return Err("settlement transaction identifiers were not derived from signed bytes".into());
    }
    Ok(())
}

fn fixture_wallet_path(document: &Value, name: &str) -> Result<WalletPath, Box<dyn Error>> {
    let value = fixture_value(document, &["derivation", name])
        .ok_or("settlement fixture has no derivation path")?;
    WalletPath::new(
        u32::try_from(fixture_u64(value, &["account"])?)?,
        fixture_bool(value, &["change"])?,
        u32::try_from(fixture_u64(value, &["address_index"])?)?,
    )
    .map_err(Into::into)
}

fn assert_fixture_hex(
    document: &Value,
    path: &[&str],
    actual: &[u8],
) -> Result<(), Box<dyn Error>> {
    if fixture_string(document, path)? != lower_hex(actual) {
        return Err("settlement construction fixture hex value changed".into());
    }
    Ok(())
}

fn fixture_value<'a>(document: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(document, |value, member| value.get(*member))
}

fn fixture_string<'a>(document: &'a Value, path: &[&str]) -> Result<&'a str, Box<dyn Error>> {
    fixture_value(document, path)
        .and_then(Value::as_str)
        .ok_or_else(|| "settlement fixture string is absent".into())
}

fn fixture_u64(document: &Value, path: &[&str]) -> Result<u64, Box<dyn Error>> {
    fixture_value(document, path)
        .and_then(Value::as_u64)
        .ok_or_else(|| "settlement fixture unsigned integer is absent".into())
}

fn fixture_bool(document: &Value, path: &[&str]) -> Result<bool, Box<dyn Error>> {
    fixture_value(document, path)
        .and_then(Value::as_bool)
        .ok_or_else(|| "settlement fixture boolean is absent".into())
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    decode_lower_hex(value)?
        .try_into()
        .map_err(|_| "settlement fixture value is not 32 bytes".into())
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err("settlement fixture hex has odd length".into());
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = lower_hex_value(*pair.first().ok_or("settlement fixture hex pair is empty")?)?;
        let low = lower_hex_value(
            *pair
                .get(1)
                .ok_or("settlement fixture hex pair is incomplete")?,
        )?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn lower_hex_value(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("settlement fixture uses non-lowercase hex".into()),
    }
}

fn temporary_seed_path(sequence: u64) -> PathBuf {
    std::env::temp_dir().join(format!(
        "immortal-provider-settlement-seed-{}-{sequence}",
        std::process::id()
    ))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
