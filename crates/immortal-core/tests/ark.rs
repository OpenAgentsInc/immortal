use immortal_core::{
    ark::{
        ArkGraphMaterial, ArkNetworkId, ArkObservedOutput, ArkOperatorDescriptor, ArkOperatorKeys,
        ArkOperatorPolicy, ArkOutpoint, ArkProtocolFamily, ArkVerificationView, ArkVtxoTerms,
        ark_vtxo_commitment_sha256, canonical_sha256, encode_hex, verify_ark_graph,
        verify_ark_pair,
    },
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, sha256, tapbranch_hash, tapleaf_hash,
        taproot_key_spend_sighash, taproot_output_key,
    },
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};

const NETWORK: &str = "bip122:0f9188f13cb7b2c9e5c30f844f792506";

#[test]
fn ark_fixture_is_byte_stable_and_verifies() {
    let (expected, descriptor, policy, material, terms, graph_sha256) = build_fixture();
    let mut actual = fixture();
    let exit_package = actual["arkade"]
        .as_object_mut()
        .and_then(|arkade| arkade.remove("exit_package"));
    assert!(exit_package.is_some_and(|value| value.is_object()));
    assert_eq!(actual, expected);
    let verified = verify_ark_graph(
        &descriptor,
        &policy,
        &material,
        &terms,
        fixture_view(),
        graph_sha256,
    )
    .expect("fixture graph must verify");
    assert_eq!(verified.selected_output.value_sat, 100_000);
    assert_eq!(verified.parent_edges, 1);
    assert_eq!(verified.transaction_ids.len(), 1);
}

#[test]
fn ark_operator_graph_and_vtxo_failures_are_typed() {
    let (_, descriptor, policy, material, terms, graph_sha256) = build_fixture();

    let mut changed_descriptor = descriptor.clone();
    changed_descriptor.protocol_version = "arkade-regtest-v2".into();
    assert_eq!(
        verify_ark_graph(
            &changed_descriptor,
            &policy,
            &material,
            &terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("operator substitution must fail")
        .code(),
        "swp_ark_operator_mismatch"
    );

    let mut changed_graph = material.clone();
    changed_graph.signed_transactions[0].replace_range(20..22, "ff");
    assert_eq!(
        verify_ark_graph(
            &descriptor,
            &policy,
            &changed_graph,
            &terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("changed graph must fail")
        .code(),
        "swp_ark_graph_invalid"
    );

    let mut changed_signature = material.clone();
    let signature_end = changed_signature.signed_transactions[0].len() - 8;
    changed_signature.signed_transactions[0].replace_range(signature_end - 2..signature_end, "00");
    let changed_signature_digest =
        canonical_sha256(&changed_signature.signed_transactions).expect("changed graph digest");
    assert_eq!(
        verify_ark_graph(
            &descriptor,
            &policy,
            &changed_signature,
            &terms,
            fixture_view(),
            changed_signature_digest,
        )
        .expect_err("invalid graph signature must fail")
        .code(),
        "swp_ark_graph_invalid"
    );

    let mut over_bounds = material.clone();
    over_bounds.signed_transactions = vec![over_bounds.signed_transactions[0].clone(); 65];
    assert_eq!(
        verify_ark_graph(
            &descriptor,
            &policy,
            &over_bounds,
            &terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("over-bounds graph must fail")
        .code(),
        "swp_ark_graph_invalid"
    );

    let mut changed_terms = terms.clone();
    changed_terms.amount_sat += 1;
    assert_eq!(
        verify_ark_graph(
            &descriptor,
            &policy,
            &material,
            &changed_terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("changed VTXO amount must fail")
        .code(),
        "swp_ark_vtxo_invalid"
    );

    let mut expired_terms = terms;
    expired_terms.expiry_value = fixture_view().block_height + 19;
    assert_eq!(
        verify_ark_graph(
            &descriptor,
            &policy,
            &material,
            &expired_terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("unsafe VTXO expiry must fail")
        .code(),
        "swp_ark_vtxo_invalid"
    );
}

#[test]
fn ark_pairs_are_operator_and_network_bound() {
    let (_, descriptor, _, _, _, _) = build_fixture();
    let ark = format!(
        "swp:1:{NETWORK}:btc:ark:arkade:{}",
        descriptor.identity_hex().expect("operator identity")
    );
    let chain = format!("swp:1:{NETWORK}:btc:chain");
    assert_eq!(verify_ark_pair(&chain, &ark), Ok(()));
    assert_eq!(
        verify_ark_pair(&ark, &ark)
            .expect_err("Ark-to-Ark must fail")
            .code(),
        "swp_invalid_pair"
    );
    assert_eq!(
        verify_ark_pair(
            "swp:1:bip122:11111111111111111111111111111111:btc:chain",
            &ark,
        )
        .expect_err("cross-network Ark pair must fail")
        .code(),
        "swp_invalid_pair"
    );
}

#[test]
fn bark_fixture_remains_a_distinct_transaction_chain_family() {
    let fixture = fixture();
    let bark = &fixture["bark"];
    let descriptor: ArkOperatorDescriptor =
        serde_json::from_value(bark["descriptor"].clone()).expect("Bark descriptor fixture");
    let policy: ArkOperatorPolicy =
        serde_json::from_value(bark["policy"].clone()).expect("Bark policy fixture");
    let (_, _, _, material, mut terms, graph_sha256) = build_fixture();
    terms.asset_id = bark["asset_id"]
        .as_str()
        .expect("Bark asset fixture")
        .to_owned();
    verify_ark_graph(
        &descriptor,
        &policy,
        &material,
        &terms,
        fixture_view(),
        graph_sha256,
    )
    .expect("Bark transaction-chain fixture must verify");

    let mut substituted = descriptor;
    substituted.protocol_family = ArkProtocolFamily::Arkade;
    assert_eq!(
        verify_ark_graph(
            &substituted,
            &policy,
            &material,
            &terms,
            fixture_view(),
            graph_sha256,
        )
        .expect_err("cross-family substitution must fail")
        .code(),
        "swp_ark_operator_mismatch"
    );
}

fn build_fixture() -> (
    Value,
    ArkOperatorDescriptor,
    ArkOperatorPolicy,
    ArkGraphMaterial,
    ArkVtxoTerms,
    [u8; 32],
) {
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_byte_array([1; 32]).expect("operator fixture key");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let operator_pubkey = operator_keypair.public_key().serialize();
    let owner_secret = SecretKey::from_byte_array([2; 32]).expect("owner fixture key");
    let owner_keypair = Keypair::from_secret_key(&secp, &owner_secret);
    let (owner_pubkey, _) = owner_keypair.x_only_public_key();
    let payment_hash = sha256(b"ark fixture payment hash");
    let claim_script = claim_script(payment_hash, owner_pubkey.serialize());
    let refund_script = refund_script(10, owner_pubkey.serialize());
    let claim_leaf = tapleaf_hash(0xc0, &claim_script).expect("claim tapleaf");
    let refund_leaf = tapleaf_hash(0xc0, &refund_script).expect("refund tapleaf");
    let merkle_root = tapbranch_hash(claim_leaf, refund_leaf);
    let (vtxo_output_key, parity) =
        taproot_output_key(owner_pubkey, Some(merkle_root)).expect("VTXO Taproot output");
    let mut claim_control_block = vec![0xc0 | u8::from(parity == secp256k1::Parity::Odd)];
    claim_control_block.extend_from_slice(&owner_pubkey.serialize());
    claim_control_block.extend_from_slice(&refund_leaf);
    let mut refund_control_block = vec![0xc0 | u8::from(parity == secp256k1::Parity::Odd)];
    refund_control_block.extend_from_slice(&owner_pubkey.serialize());
    refund_control_block.extend_from_slice(&claim_leaf);

    let anchor = ArkOutpoint::parse(&format!("{}:0", "aa".repeat(32))).expect("anchor outpoint");
    let anchor_output = TransactionOutput {
        value_sat: 112_000,
        script_pubkey: p2tr_script(operator_keypair.x_only_public_key().0.serialize()),
    };
    let mut transfer = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid: consensus_txid(anchor.transaction_id()),
            previous_output: anchor.output_index(),
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        vec![
            TransactionOutput {
                value_sat: 100_000,
                script_pubkey: p2tr_script(vtxo_output_key.serialize()),
            },
            TransactionOutput {
                value_sat: 10_000,
                script_pubkey: p2tr_script(owner_pubkey.serialize()),
            },
        ],
        0,
    );
    let sighash = taproot_key_spend_sighash(&transfer, core::slice::from_ref(&anchor_output), 0)
        .expect("transfer sighash");
    let signature = secp.sign_schnorr_no_aux_rand(&sighash, &operator_keypair);
    transfer
        .set_input_witness(0, vec![signature.as_ref().to_vec()])
        .expect("transfer witness");
    let transfer_raw = transfer.serialize(true).expect("signed transfer bytes");
    let transfer_id = transfer.txid().expect("transfer ID");
    let selected = ArkOutpoint::from_parts(transfer_id, 0);

    let policy = ArkOperatorPolicy {
        network_id: NETWORK.into(),
        protocol_family: ArkProtocolFamily::Arkade,
        protocol_version: "arkade-regtest-v1".into(),
        minimum_vtxo_amount: "1".into(),
        maximum_vtxo_amount: "10000000".into(),
        maximum_input_vtxos: 32,
        maximum_graph_transactions: 64,
        maximum_parent_edges: 32,
        maximum_graph_bytes: 262_144,
        maximum_transaction_weight: 400_000,
        expiry_domain: "block_height".into(),
        minimum_expiry_delta: "20".into(),
        unilateral_exit_domain: "blocks".into(),
        unilateral_exit_delay: "10".into(),
        checkpoint_script_sha256: encode_hex(&sha256(b"arkade fixture checkpoint")),
        fee_rule_sha256: encode_hex(&sha256(b"arkade fixture fee rule")),
    };
    let descriptor = ArkOperatorDescriptor {
        network_id: ArkNetworkId::parse(NETWORK).expect("network"),
        protocol_family: ArkProtocolFamily::Arkade,
        protocol_version: policy.protocol_version.clone(),
        operator_keys: ArkOperatorKeys {
            signer_pubkey: Some(encode_hex(&operator_pubkey)),
            forfeit_pubkey: Some(encode_hex(&owner_keypair.public_key().serialize())),
            server_pubkey: None,
        },
        operator_policy_sha256: policy.digest_hex().expect("policy digest"),
    };
    let operator_identity = descriptor.identity_hex().expect("operator identity");
    let asset_id = format!("swp:1:{NETWORK}:btc:ark:arkade:{operator_identity}");
    let mut bark_policy = policy.clone();
    bark_policy.protocol_family = ArkProtocolFamily::Bark;
    bark_policy.protocol_version = "bark-regtest-v1".into();
    let bark_descriptor = ArkOperatorDescriptor {
        network_id: ArkNetworkId::parse(NETWORK).expect("Bark network"),
        protocol_family: ArkProtocolFamily::Bark,
        protocol_version: bark_policy.protocol_version.clone(),
        operator_keys: ArkOperatorKeys {
            signer_pubkey: None,
            forfeit_pubkey: None,
            server_pubkey: Some(encode_hex(&operator_pubkey)),
        },
        operator_policy_sha256: bark_policy.digest_hex().expect("Bark policy digest"),
    };
    let bark_identity = bark_descriptor
        .identity_hex()
        .expect("Bark operator identity");
    let bark_asset_id = format!("swp:1:{NETWORK}:btc:ark:bark:{bark_identity}");
    let signed_transactions = vec![encode_hex(&transfer_raw)];
    let graph_sha256 = canonical_sha256(&signed_transactions).expect("graph digest");
    let terms = ArkVtxoTerms {
        asset_id: asset_id.clone(),
        input_vtxo_ids: vec![anchor.clone()],
        output_vtxo_id: selected.clone(),
        amount_sat: 100_000,
        owner_pubkey: encode_hex(&owner_pubkey.serialize()),
        payment_hash,
        claim_script: claim_script.clone(),
        claim_control_block: claim_control_block.clone(),
        refund_script: refund_script.clone(),
        refund_control_block: refund_control_block.clone(),
        claim_path_sha256: sha256(&claim_script),
        refund_path_sha256: sha256(&refund_script),
        expiry_domain: "block_height".into(),
        expiry_value: 500,
        unilateral_exit_domain: "blocks".into(),
        unilateral_exit_delay: 10,
        anchor_outpoint: anchor.clone(),
    };
    let material = ArkGraphMaterial {
        signed_transactions: signed_transactions.clone(),
        observed_outputs: vec![ArkObservedOutput {
            outpoint: anchor.clone(),
            output: anchor_output.clone(),
        }],
    };
    let fixture = json!({
        "schema": "openagents.mkt-swp.ark-fixtures.v1",
        "source": {
            "commit": "c241e324e4a195c6a1fcbb04acc54647c2fa2208",
            "specification": "nips/openagents/MKT-SWP.md"
        },
        "limits": {
            "input_vtxos": 32,
            "graph_transactions": 64,
            "parent_edges": 32,
            "decoded_graph_bytes": 262144
        },
        "arkade": {
            "descriptor": descriptor,
            "operator_identity_sha256": operator_identity,
            "policy": policy,
            "asset_id": asset_id,
            "anchor": {
                "outpoint": anchor.canonical(),
                "amount": anchor_output.value_sat.to_string(),
                "script_pubkey": encode_hex(&anchor_output.script_pubkey)
            },
            "signed_vtxo_graph": signed_transactions,
            "signed_vtxo_graph_sha256": encode_hex(&graph_sha256),
            "vtxo": {
                "outpoint": selected.canonical(),
                "amount": terms.amount_sat.to_string(),
                "owner_pubkey": terms.owner_pubkey,
                "payment_hash": encode_hex(&terms.payment_hash),
                "claim_script": encode_hex(&terms.claim_script),
                "claim_control_block": encode_hex(&terms.claim_control_block),
                "claim_path_sha256": encode_hex(&terms.claim_path_sha256),
                "refund_script": encode_hex(&terms.refund_script),
                "refund_control_block": encode_hex(&terms.refund_control_block),
                "refund_path_sha256": encode_hex(&terms.refund_path_sha256),
                "expiry": {"domain":"block_height","value":"500"},
                "unilateral_exit_delay": {"domain":"blocks","value":"10"},
                "commitment_sha256": encode_hex(&ark_vtxo_commitment_sha256(&terms).expect("VTXO commitment"))
            }
        },
        "bark": {
            "descriptor": bark_descriptor,
            "operator_identity_sha256": bark_identity,
            "policy": bark_policy,
            "asset_id": bark_asset_id
        },
        "cases": {
            "positive": [
                "swp-v1-arkade-submarine-vtxo",
                "swp-v1-bark-reverse-vtxo",
                "swp-v1-ark-chain-regtest",
                "swp-v1-ark-covenant-hard-reservation",
                "swp-v1-ark-exit-keyless"
            ],
            "negative": {
                "swp-v1-negative-ark-operator-identity": "swp_ark_operator_mismatch",
                "swp-v1-negative-ark-family-substitution": "swp_ark_operator_mismatch",
                "swp-v1-negative-ark-cross-operator-pair": "swp_invalid_pair",
                "swp-v1-negative-ark-cross-network-pair": "swp_invalid_pair",
                "swp-v1-negative-ark-graph-cycle": "swp_ark_graph_invalid",
                "swp-v1-negative-ark-graph-over-bounds": "swp_ark_graph_invalid",
                "swp-v1-negative-ark-graph-signature": "swp_ark_graph_invalid",
                "swp-v1-negative-ark-vtxo-owner": "swp_ark_vtxo_invalid",
                "swp-v1-negative-ark-vtxo-amount": "swp_ark_vtxo_invalid",
                "swp-v1-negative-ark-vtxo-expiry": "swp_ark_vtxo_invalid",
                "swp-v1-negative-ark-exit-incomplete": "swp_ark_exit_unsafe",
                "swp-v1-negative-ark-exit-safe-start": "swp_ark_exit_unsafe",
                "swp-v1-negative-ark-exit-fee-key": "swp_secret_material_forbidden",
                "swp-v1-negative-ark-exit-condition-preimage": "swp_secret_material_forbidden"
            },
            "reservation": ["swp-v1-ark-reserve-double-use"],
            "privacy": [
                "swp-v1-privacy-ark-operator-token-tripwire",
                "swp-v1-privacy-ark-vtxo-key-tripwire",
                "swp-v1-privacy-ark-raw-exit-package-tripwire"
            ],
            "recovery": [
                "swp-v1-doomsday-ark-operator-gone",
                "swp-v1-ark-exit-deadline-recovery"
            ]
        }
    });
    (fixture, descriptor, policy, material, terms, graph_sha256)
}

fn claim_script(payment_hash: [u8; 32], owner_pubkey: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
    script.extend_from_slice(&payment_hash);
    script.extend_from_slice(&[0x88, 0x20]);
    script.extend_from_slice(&owner_pubkey);
    script.push(0xac);
    script
}

fn refund_script(delay: u8, owner_pubkey: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0x01, delay, 0xb2, 0x75, 0x20];
    script.extend_from_slice(&owner_pubkey);
    script.push(0xac);
    script
}

fn p2tr_script(output_key: [u8; 32]) -> Vec<u8> {
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&output_key);
    script
}

fn consensus_txid(mut transaction_id: [u8; 32]) -> [u8; 32] {
    transaction_id.reverse();
    transaction_id
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/ark-rail-v1.json"
    ))
    .expect("Ark fixture JSON")
}

fn fixture_view() -> ArkVerificationView {
    ArkVerificationView {
        block_height: 400,
        unix_time: 1_785_859_200,
    }
}
