use immortal_client::liquid::{
    LiquidBeforeFundRequest, LiquidConfidentiality, LiquidExitMode, LiquidFundingAuthorization,
    LiquidFundingVerificationInput, LiquidLegPurpose, LiquidLegVerifier, LiquidNodeAuthority,
    LiquidSwapType, LiquidUnilateralExitPackage, LocalLiquidNodeObservation,
    LocalLiquidObservation, LocalLiquidUnblind, verify_wallet_signed_exit,
};
use immortal_client::mkt_swp_client::provider_support;
use immortal_core::{
    liquid::{
        LiquidAssetId, LiquidGenesisHash, LiquidNetworkId, LiquidPrevout,
        liquid_taproot_script_spend_sighash, parse_liquid_transaction, sign_liquid_taproot_sighash,
    },
    mkt_swp_verify::{parse_swap_leaf_script, sha256},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

const NETWORK: &str = "bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ASSET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BITCOIN_NETWORK: &str = "bip122:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INTERNAL_KEY: &str = "08228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968";
const ORIGINAL_OUTPUT_KEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct ExitPath {
    output_key: &'static str,
    merkle_root: &'static str,
    script: &'static str,
    control_block: &'static str,
    path: &'static str,
    timelock: u32,
}

const REFUND: ExitPath = ExitPath {
    output_key: "6f28a027ecd92a3d9af9798d032bc0040310a15a5dd7c0e0abb8ea8959523009",
    merkle_root: "be8e5d61bd9415b53af92f729857dfeeabd4e26a7827ec20d7ce99703d21548c",
    script: "028c00b17520716022efaca232dd8a7927619a9e5f1eb8f1c8b87436a52a03ae7e1239a1662aac",
    control_block: "c408228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968ad4f0cd39b48ad95bd00c6f1f1d08ff3a776c62c9c0e7832b71cdf87d5834bcd",
    path: "refund",
    timelock: 140,
};

const CLAIM: ExitPath = ExitPath {
    output_key: "e299c811d598407b65670e5b11eca62be410095cbb0cce80e782bec4d6fb19fb",
    merkle_root: "3158fb84c8a56733a5d1bcd080d90097b4cf7456bbcf2736d028ac0d588dde3e",
    script: "82012088a820a8cdda70ab7c99dc8dc6a38f979a908a92177eb0dd689770417a5b9a92f78af3882033def30752282502724206c0e18eebed01b436a81cc6ed8b0476f4aaee151ce4ac",
    control_block: "c408228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d9685146765099b4d9f38c16ba9664d855287be8e74c1ae9f80f6980672166ace146",
    path: "claim",
    timelock: 0,
};

#[test]
fn liquid_fixture_names_all_executable_client_cases() {
    let fixture = fixture();
    let names = fixture["client_vectors"]
        .as_array()
        .expect("client vectors")
        .iter()
        .map(|case| case["name"].as_str().expect("case name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "swp-v1-liquid-submarine-regtest-refund",
            "swp-v1-liquid-reverse-regtest-claim",
            "swp-v1-btc-liquid-chain-regtest",
            "swp-v1-negative-liquid-exit-outpoint",
            "swp-v1-negative-liquid-exit-witness",
            "swp-v1-negative-liquid-exit-preimage",
            "swp-v1-negative-liquid-exit-script-witness",
            "swp-v1-negative-liquid-exit-control-block-witness",
            "swp-v1-negative-liquid-exit-genesis",
            "swp-v1-negative-liquid-exit-schema",
            "swp-v1-liquid-exit-optional-taproot-tree",
            "swp-v1-negative-liquid-exit-unknown-member",
            "swp-v1-privacy-liquid-blinding-key-tripwire",
            "swp-v1-negative-btc-liquid-destination-signature",
            "swp-v1-negative-btc-liquid-destination-mempool",
            "swp-v1-negative-btc-liquid-source-before-preflight",
            "swp-v1-negative-cross-signer-status-prepublish",
            "swp-v1-negative-liquid-chain-terminal-refund-without-source-release",
            "swp-v1-negative-requester-claims-source-funding-required",
        ]
    );
    assert_eq!(
        fixture["client_vectors"][1]["pre_fund_node_requirement"],
        "confirmed_lock"
    );
    assert_eq!(
        fixture["client_vectors"][2]["pre_fund_node_requirement"],
        "mempool_acceptance_of_exact_unbroadcast_template"
    );
    assert_eq!(
        fixture["client_vectors"][2]["source_funding_required_signer"],
        "provider"
    );
    assert_eq!(
        fixture["client_vectors"][2]["requester_source_broadcast_base_state"],
        "funding_observed"
    );
    assert_eq!(
        fixture["client_vectors"][2]["provider_destination_broadcast_base_state"],
        "funding_observed"
    );
}

#[test]
fn liquid_submarine_reverse_and_chain_verify_before_fund() {
    let verifier = verifier();
    let cases = [
        (
            LiquidSwapType::Submarine,
            LiquidLegPurpose::RequesterBroadcast,
            liquid_asset(),
            format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
            &REFUND,
        ),
        (
            LiquidSwapType::Reverse,
            LiquidLegPurpose::CounterpartyLock,
            format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
            liquid_asset(),
            &CLAIM,
        ),
        (
            LiquidSwapType::Chain,
            LiquidLegPurpose::CounterpartyLock,
            format!("swp:1:{BITCOIN_NETWORK}:btc:chain"),
            liquid_asset(),
            &CLAIM,
        ),
        (
            LiquidSwapType::Chain,
            LiquidLegPurpose::RequesterBroadcast,
            liquid_asset(),
            format!("swp:1:{BITCOIN_NETWORK}:btc:chain"),
            &REFUND,
        ),
    ];
    for (swap_type, purpose, input_asset_id, output_asset_id, exit) in cases {
        let request = request(
            swap_type,
            purpose,
            input_asset_id,
            output_asset_id,
            exit,
            true,
        );
        let verified = verifier
            .verify_before_fund(&request, |node_request| {
                Ok(LocalLiquidObservation {
                    transaction_id: node_request.transaction_id.clone(),
                    transaction_sha256: node_request.transaction_sha256.clone(),
                    confirmations: u32::from(
                        purpose == LiquidLegPurpose::CounterpartyLock
                            && swap_type != LiquidSwapType::Chain,
                    ),
                    mempool_accepted: purpose == LiquidLegPurpose::RequesterBroadcast
                        || swap_type == LiquidSwapType::Chain,
                    replacement_detected: false,
                    competing_spend_detected: false,
                })
            })
            .expect("Liquid leg verifies");
        assert_eq!(verified.amount_sat, 100_000);
        assert_eq!(verified.output_index, 0);
        match (purpose, verified.authorization) {
            (
                LiquidLegPurpose::RequesterBroadcast,
                LiquidFundingAuthorization::BroadcastLiquid { .. },
            )
            | (
                LiquidLegPurpose::CounterpartyLock,
                LiquidFundingAuthorization::ContinueAfterLiquidLock { .. },
            ) => {}
            other => panic!("unexpected Liquid authorization: {other:?}"),
        }
    }
}

#[test]
fn liquid_counterparty_lock_distinguishes_chain_template_from_reverse_finality() {
    let fixture = fixture();
    let verifier = verifier();
    let reverse = request(
        LiquidSwapType::Reverse,
        LiquidLegPurpose::CounterpartyLock,
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        liquid_asset(),
        &CLAIM,
        true,
    );
    let chain = request(
        LiquidSwapType::Chain,
        LiquidLegPurpose::CounterpartyLock,
        format!("swp:1:{BITCOIN_NETWORK}:btc:chain"),
        liquid_asset(),
        &CLAIM,
        true,
    );
    let observe = |request: &LiquidBeforeFundRequest, confirmations, mempool_accepted| {
        verifier.verify_before_fund(request, |node_request| {
            Ok(LocalLiquidObservation {
                transaction_id: node_request.transaction_id.clone(),
                transaction_sha256: node_request.transaction_sha256.clone(),
                confirmations,
                mempool_accepted,
                replacement_detected: false,
                competing_spend_detected: false,
            })
        })
    };

    assert_eq!(
        observe(&reverse, 0, true).unwrap_err().code,
        "swp_confirmation_insufficient"
    );
    assert_eq!(
        observe(&chain, 1, true).unwrap_err().code,
        "swp_liquid_output_invalid"
    );
    assert_eq!(
        observe(&chain, 0, false).unwrap_err().code,
        client_vector_expected(&fixture, "swp-v1-negative-btc-liquid-destination-mempool")
    );
    assert_eq!(
        verifier
            .verify_before_fund(&chain, |_request| {
                Err("local mempool policy rejected the exact template".to_owned())
            })
            .unwrap_err()
            .code,
        client_vector_expected(&fixture, "swp-v1-negative-btc-liquid-destination-mempool")
    );
    observe(&chain, 0, true).unwrap();
}

#[test]
fn liquid_production_adapter_binds_the_exact_full_genesis_hash() {
    let verifier = verifier();
    let mut request = request(
        LiquidSwapType::Reverse,
        LiquidLegPurpose::CounterpartyLock,
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        liquid_asset(),
        &CLAIM,
        false,
    );
    let (_, unblinded_transaction) = funding_transactions(CLAIM.output_key);
    request.funding.trusted_unblind_transaction = None;
    let error = verifier
        .verify_before_fund_with_local_adapters(
            &request,
            |adapter_request| {
                Ok(LocalLiquidUnblind {
                    authority: LiquidNodeAuthority::LocalElementsd,
                    network_id: adapter_request.network_id.clone(),
                    pegged_asset: ASSET.to_owned(),
                    transaction_sha256: adapter_request.transaction_sha256.clone(),
                    output_index: adapter_request.output_index,
                    unblinded_transaction: unblinded_transaction.clone(),
                })
            },
            |node_request| {
                Ok(LocalLiquidNodeObservation {
                    authority: LiquidNodeAuthority::LocalElementsd,
                    network_id: NETWORK.to_owned(),
                    genesis_hash: format!("{}b", "a".repeat(63)),
                    pegged_asset: ASSET.to_owned(),
                    observation: LocalLiquidObservation {
                        transaction_id: node_request.transaction_id.clone(),
                        transaction_sha256: node_request.transaction_sha256.clone(),
                        confirmations: 1,
                        mempool_accepted: true,
                        replacement_detected: false,
                        competing_spend_detected: false,
                    },
                })
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "swp_liquid_output_invalid");
    assert!(error.detail.contains("genesis") || error.detail.contains("network"));
}

#[test]
fn liquid_chain_destination_signature_fixture_rejects_changed_signed_bytes() {
    let fixture = fixture();
    let chain = request(
        LiquidSwapType::Chain,
        LiquidLegPurpose::CounterpartyLock,
        format!("swp:1:{BITCOIN_NETWORK}:btc:chain"),
        liquid_asset(),
        &CLAIM,
        true,
    );
    let mut signed = wallet_signed_exit(&chain, &CLAIM);
    replace_raw_exit_witness_item(&mut signed, 0, &[1_u8; 64]);

    assert_eq!(
        verify_wallet_signed_exit(&chain, &signed).unwrap_err().code,
        client_vector_expected(&fixture, "swp-v1-negative-btc-liquid-destination-signature")
    );
}

#[test]
fn liquid_refuses_unblind_outpoint_witness_and_secret_failures() {
    let verifier = verifier();
    let mut wrong_amount = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        true,
    );
    wrong_amount.funding.amount = "100001".to_owned();
    assert_eq!(
        verify(&verifier, &wrong_amount),
        "swp_liquid_unblind_mismatch"
    );

    let mut wrong_outpoint = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        true,
    );
    wrong_outpoint.exit_package.funding_output_index = 1;
    assert_eq!(
        verify(&verifier, &wrong_outpoint),
        "swp_exit_package_mismatch"
    );

    let missing_witness = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        false,
    );
    assert_eq!(
        verify(&verifier, &missing_witness),
        "swp_exit_package_unusable"
    );

    let mut document =
        serde_json::to_value(&missing_witness.exit_package).expect("exit package JSON");
    document["blinding_key"] = Value::String("forbidden".to_owned());
    let liquid_fixture = fixture();
    let expected = liquid_fixture["client_vectors"]
        .as_array()
        .expect("client vectors")
        .iter()
        .find(|case| case["name"].as_str() == Some("swp-v1-privacy-liquid-blinding-key-tripwire"))
        .and_then(|case| case["expected"].as_str())
        .expect("blinding tripwire expectation");
    assert_eq!(
        provider_support::reject_custody_material(&document)
            .expect_err("Liquid blinding material must be rejected")
            .code,
        expected
    );
}

#[test]
fn liquid_exit_rejects_wallet_preimage_and_presigned_path_or_genesis_mutations() {
    let fixture = fixture();
    let verifier = verifier();
    let preimage = request(
        LiquidSwapType::Reverse,
        LiquidLegPurpose::CounterpartyLock,
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        liquid_asset(),
        &CLAIM,
        true,
    );
    let mut signed = wallet_signed_exit(&preimage, &CLAIM);
    replace_raw_exit_witness_item(&mut signed, 1, &[2_u8; 32]);
    assert_eq!(
        verify_wallet_signed_exit(&preimage, &signed)
            .unwrap_err()
            .code,
        client_vector_expected(&fixture, "swp-v1-negative-liquid-exit-preimage")
    );

    let mut script = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        true,
    );
    mutate_exit_witness_item(&mut script, 1);
    assert_eq!(
        verify(&verifier, &script),
        client_vector_expected(&fixture, "swp-v1-negative-liquid-exit-script-witness")
    );

    let mut control_block = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        true,
    );
    mutate_exit_witness_item(&mut control_block, 2);
    assert_eq!(
        verify(&verifier, &control_block),
        client_vector_expected(
            &fixture,
            "swp-v1-negative-liquid-exit-control-block-witness"
        )
    );

    let mut genesis = request(
        LiquidSwapType::Submarine,
        LiquidLegPurpose::RequesterBroadcast,
        liquid_asset(),
        format!("swp:1:{BITCOIN_NETWORK}:btc:lightning"),
        &REFUND,
        true,
    );
    genesis.exit_package.genesis_hash = format!("{}b", "a".repeat(63));
    assert_eq!(
        verify(&verifier, &genesis),
        client_vector_expected(&fixture, "swp-v1-negative-liquid-exit-genesis")
    );
}

fn verify(verifier: &LiquidLegVerifier, request: &LiquidBeforeFundRequest) -> &'static str {
    let confirmations = u32::from(!matches!(
        (request.swap_type, request.purpose),
        (LiquidSwapType::Chain, LiquidLegPurpose::CounterpartyLock)
    ));
    verifier
        .verify_before_fund(request, |node_request| {
            Ok(LocalLiquidObservation {
                transaction_id: node_request.transaction_id.clone(),
                transaction_sha256: node_request.transaction_sha256.clone(),
                confirmations,
                mempool_accepted: true,
                replacement_detected: false,
                competing_spend_detected: false,
            })
        })
        .expect_err("Liquid mutation is rejected")
        .code
}

fn request(
    swap_type: LiquidSwapType,
    purpose: LiquidLegPurpose,
    input_asset_id: String,
    output_asset_id: String,
    exit: &ExitPath,
    signed_exit: bool,
) -> LiquidBeforeFundRequest {
    let (funding_hex, unblind_hex) = funding_transactions(exit.output_key);
    let funding_raw = decode_hex(&funding_hex);
    let funding = parse_liquid_transaction(&funding_raw).expect("funding transaction");
    let exit_raw = if exit.path == "claim" {
        exit_transaction(funding.transaction_id, exit.output_key, exit, None)
    } else if signed_exit {
        signed_exit_transaction(&funding, exit.output_key, exit)
    } else {
        exit_transaction(funding.transaction_id, exit.output_key, exit, None)
    };
    LiquidBeforeFundRequest {
        swap_type,
        purpose,
        input_asset_id,
        output_asset_id,
        funding: LiquidFundingVerificationInput {
            raw_transaction: funding_hex,
            trusted_unblind_transaction: Some(unblind_hex),
            transaction_sha256: encode_hex(&sha256(&funding_raw)),
            output_index: 0,
            asset_id: liquid_asset(),
            amount: "100000".to_owned(),
            script_pubkey: format!("5120{}", exit.output_key),
            taproot_internal_key: INTERNAL_KEY.to_owned(),
            taproot_merkle_root: Some(exit.merkle_root.to_owned()),
            confidentiality: LiquidConfidentiality::Confidential,
            minimum_confirmations: 1,
            replacement_policy: "reject".to_owned(),
        },
        exit_package: LiquidUnilateralExitPackage {
            schema: "openagents.mkt-swp.liquid-exit.v1".to_owned(),
            genesis_hash: GENESIS_HASH.to_owned(),
            network_id: NETWORK.to_owned(),
            asset_id: liquid_asset(),
            funding_transaction_id: encode_hex(&funding.transaction_id),
            funding_output_index: 0,
            funding_amount: "100000".to_owned(),
            funding_script_pubkey: format!("5120{}", exit.output_key),
            path: exit.path.to_owned(),
            script: exit.script.to_owned(),
            control_block: exit.control_block.to_owned(),
            timelock: exit.timelock,
            spend_input_index: 0,
            fee_output_index: 1,
            fee_amount: "500".to_owned(),
            transaction_sha256: encode_hex(&sha256(&exit_raw)),
            transaction: encode_hex(&exit_raw),
            mode: if exit.path == "claim" {
                LiquidExitMode::Wallet
            } else {
                LiquidExitMode::Presigned
            },
            wallet_signing_handle_sha256: (exit.path == "claim").then(|| "44".repeat(32)),
            preimage_recovery_ref: (exit.path == "claim").then(|| "45".repeat(32)),
        },
    }
}

fn funding_transactions(output_key: &str) -> (String, String) {
    let fixture = fixture();
    let vector = &fixture["parser_vectors"][0];
    let replace = |value: &str| {
        value.replace(
            &format!("5120{ORIGINAL_OUTPUT_KEY}"),
            &format!("5120{output_key}"),
        )
    };
    (
        replace(vector["raw_transaction"].as_str().expect("raw transaction")),
        replace(
            vector["trusted_local_unblind"]
                .as_str()
                .expect("trusted unblind"),
        ),
    )
}

fn exit_transaction(
    funding_transaction_id: [u8; 32],
    destination_key: &str,
    exit: &ExitPath,
    signature: Option<[u8; 64]>,
) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&2_i32.to_le_bytes());
    raw.push(u8::from(signature.is_some()));
    raw.push(1);
    let mut wire_transaction_id = funding_transaction_id;
    wire_transaction_id.reverse();
    raw.extend_from_slice(&wire_transaction_id);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0);
    let sequence = if exit.path == "refund" {
        0xffff_fffe
    } else {
        u32::MAX
    };
    raw.extend_from_slice(&sequence.to_le_bytes());
    raw.push(2);
    push_explicit_output(
        &mut raw,
        99_500,
        &decode_hex(&format!("5120{destination_key}")),
    );
    push_explicit_output(&mut raw, 500, &[]);
    raw.extend_from_slice(&exit.timelock.to_le_bytes());
    if let Some(signature) = signature {
        raw.push(0);
        raw.push(0);
        let script = decode_hex(exit.script);
        let control_block = decode_hex(exit.control_block);
        let witness_count = if exit.path == "claim" { 4 } else { 3 };
        raw.push(witness_count);
        push_bytes(&mut raw, &signature);
        if exit.path == "claim" {
            push_bytes(&mut raw, &test_released_preimage());
        }
        push_bytes(&mut raw, &script);
        push_bytes(&mut raw, &control_block);
        raw.push(0);
        for _ in 0..2 {
            raw.push(0);
            raw.push(0);
        }
    }
    raw
}

fn signed_exit_transaction(
    funding: &immortal_core::liquid::LiquidTransaction,
    destination_key: &str,
    exit: &ExitPath,
) -> Vec<u8> {
    let unsigned = exit_transaction(funding.transaction_id, destination_key, exit, None);
    let transaction = parse_liquid_transaction(&unsigned).expect("unsigned exit transaction");
    let funding_output = funding.outputs.first().expect("funding output");
    let prevout = LiquidPrevout {
        asset: funding_output.asset.clone(),
        value: funding_output.value.clone(),
        script_pubkey: funding_output.script_pubkey.clone(),
    };
    let script = decode_hex(exit.script);
    let control_block = decode_hex(exit.control_block);
    let sighash = liquid_taproot_script_spend_sighash(
        &transaction,
        &[prevout],
        0,
        LiquidGenesisHash::parse_display(GENESIS_HASH).expect("genesis hash"),
        &script,
        &control_block,
        None,
    )
    .expect("exit sighash");
    let signer_label = if exit.path == "claim" {
        b"exit:destination:claim".as_slice()
    } else {
        b"exit:source:refund".as_slice()
    };
    let secret = SecretKey::from_byte_array(test_signing_key(signer_label)).expect("exit key");
    let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
    assert_eq!(
        keypair.x_only_public_key().0,
        parse_swap_leaf_script(&script)
            .expect("exit leaf")
            .signing_key
    );
    let signature = sign_liquid_taproot_sighash(sighash, &keypair);
    exit_transaction(
        funding.transaction_id,
        destination_key,
        exit,
        Some(signature),
    )
}

fn wallet_signed_exit(request: &LiquidBeforeFundRequest, exit: &ExitPath) -> Vec<u8> {
    let funding = parse_liquid_transaction(&decode_hex(&request.funding.raw_transaction))
        .expect("wallet funding transaction");
    signed_exit_transaction(&funding, exit.output_key, exit)
}

fn mutate_exit_witness_item(request: &mut LiquidBeforeFundRequest, item_index: usize) {
    let transaction = parse_liquid_transaction(&decode_hex(&request.exit_package.transaction))
        .expect("exit transaction");
    let item = transaction.inputs[0]
        .script_witness
        .get(item_index)
        .expect("witness item");
    let mut raw = decode_hex(&request.exit_package.transaction);
    let offset = raw
        .windows(item.len())
        .position(|candidate| candidate == item)
        .expect("witness bytes in transaction");
    raw[offset] ^= 1;
    request.exit_package.transaction_sha256 = encode_hex(&sha256(&raw));
    request.exit_package.transaction = encode_hex(&raw);
}

fn replace_raw_exit_witness_item(raw: &mut [u8], item_index: usize, replacement: &[u8]) {
    let transaction = parse_liquid_transaction(raw).expect("exit transaction");
    let item = transaction.inputs[0]
        .script_witness
        .get(item_index)
        .expect("witness item");
    assert_eq!(item.len(), replacement.len());
    let offset = raw
        .windows(item.len())
        .position(|candidate| candidate == item)
        .expect("witness bytes in transaction");
    raw[offset..offset + item.len()].copy_from_slice(replacement);
}

fn test_released_preimage() -> [u8; 32] {
    sha256(b"immortal-mkt-swp-test-only:released-preimage")
}

fn test_signing_key(role: &[u8]) -> [u8; 32] {
    Sha256::digest([b"immortal-mkt-swp-test-only:".as_slice(), role].concat()).into()
}

fn push_explicit_output(raw: &mut Vec<u8>, amount: u64, script_pubkey: &[u8]) {
    raw.push(1);
    raw.extend_from_slice(&[0x11; 32]);
    raw.push(1);
    raw.extend_from_slice(&amount.to_be_bytes());
    raw.push(0);
    push_bytes(raw, script_pubkey);
}

fn push_bytes(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.push(u8::try_from(bytes.len()).expect("fixture field stays below compact-size prefix"));
    raw.extend_from_slice(bytes);
}

fn verifier() -> LiquidLegVerifier {
    LiquidLegVerifier::new(
        LiquidNetworkId::parse(NETWORK).expect("network"),
        LiquidAssetId::parse(ASSET).expect("asset"),
    )
}

fn liquid_asset() -> String {
    format!("swp:1:{NETWORK}:elements:{ASSET}:liquid")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/liquid-rail-v1.json"
    ))
    .expect("Liquid fixture")
}

fn client_vector_expected<'a>(fixture: &'a Value, name: &str) -> &'a str {
    fixture["client_vectors"]
        .as_array()
        .expect("client vectors")
        .iter()
        .find(|case| case["name"] == name)
        .and_then(|case| case["expected"].as_str())
        .expect("client vector expected error")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
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

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture hex is lowercase"),
    }
}
