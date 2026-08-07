use immortal_client::ark::{
    ArkBroadcastPolicy, ArkClientEngine, ArkContractBinding, ArkDomainValue, ArkExitFeePolicy,
    ArkExitFunding, ArkExitPackage, ArkExitPlan, ArkExitVerification, ArkExitVerificationInput,
    ArkKnownTransaction, ArkPersistenceReceipt, ArkSecretCommitments, ArkSignedExitTransaction,
};
use immortal_core::{
    ark::{
        ArkGraphMaterial, ArkObservedOutput, ArkOperatorDescriptor, ArkOperatorPolicy, ArkOutpoint,
        ArkVerificationView, ArkVtxoTerms, ark_vtxo_commitment_sha256, canonical_json, encode_hex,
    },
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, sha256, taproot_key_spend_sighash,
        taproot_script_spend_sighash,
    },
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::Value;

const BLOCK_HEIGHT: u64 = 400;

#[test]
fn ark_exit_is_persisted_before_transfer_and_snapshot_keeps_only_a_reference() {
    let fixture = Fixture::from_json();
    let package = fixture.package();
    assert_eq!(
        fixture.json["arkade"]["exit_package"],
        serde_json::to_value(&package).expect("Ark exit package JSON")
    );
    let bytes = canonical_json(&package).expect("canonical Ark package");
    let binding = fixture.binding(&bytes);
    let input = fixture.input(&binding);
    let (engine, persistence) =
        ArkClientEngine::prepare(&bytes, &input).expect("verified Ark package");
    assert_eq!(persistence.canonical_package, bytes);
    assert_eq!(persistence.artifact_sha256, binding.exit_package_sha256);
    assert_eq!(
        engine
            .authorize_transfer()
            .expect_err("transfer before persistence must fail")
            .code,
        "swp_funding_not_authorized"
    );

    let engine = engine
        .confirm_persistence(ArkPersistenceReceipt {
            artifact_sha256: persistence.artifact_sha256,
            artifact_ref: "private-artifacts/ark/order-66/exit-v1".into(),
        })
        .expect("persistence receipt");
    let authorization = engine.authorize_transfer().expect("Ark transfer gate");
    assert_eq!(authorization.action, "ark_transfer");
    assert_eq!(authorization.vtxo_id, package.funding.vtxo_id);

    let snapshot = engine.snapshot().expect("Ark client snapshot");
    let snapshot_text = core::str::from_utf8(&snapshot).expect("snapshot UTF-8");
    assert!(!snapshot_text.contains(&package.exit.signed_transactions[0].signed_transaction));
    assert!(!snapshot_text.contains("signed_vtxo_graph"));
    assert!(!snapshot_text.contains("payment_hash"));
    let restored = ArkClientEngine::restore(&snapshot).expect("restore Ark client snapshot");
    assert_eq!(
        restored
            .authorize_transfer()
            .expect("restored transfer gate"),
        authorization
    );
}

#[test]
fn keyless_executor_waits_replays_exact_bytes_and_rejects_a_witness_conflict() {
    let fixture = Fixture::from_json();
    let package = fixture.package();
    let bytes = canonical_json(&package).expect("canonical Ark package");
    let binding = fixture.binding(&bytes);
    let input = fixture.input(&binding);
    let (engine, persistence) =
        ArkClientEngine::prepare(&bytes, &input).expect("verified Ark package");
    let engine = engine
        .confirm_persistence(ArkPersistenceReceipt {
            artifact_sha256: persistence.artifact_sha256,
            artifact_ref: "private-artifacts/ark/keyless-exit".into(),
        })
        .expect("persistence receipt");
    assert_eq!(
        engine
            .next_broadcast_request(&bytes, "http://127.0.0.1:3002/api", 409, &[])
            .expect("pre-window request"),
        None
    );
    let request = engine
        .next_broadcast_request(&bytes, "http://127.0.0.1:3002/api", 410, &[])
        .expect("keyless request")
        .expect("transaction is ready");
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "http://127.0.0.1:3002/api/tx");
    assert_eq!(
        request.body,
        package.exit.signed_transactions[0].signed_transaction
    );
    let known = [ArkKnownTransaction {
        transaction_id: request.transaction_id.clone(),
        signed_transaction_sha256: request.signed_transaction_sha256.clone(),
    }];
    assert_eq!(
        engine
            .next_broadcast_request(&bytes, "http://127.0.0.1:3002/api", 410, &known)
            .expect("exact already-known transaction"),
        None
    );
    let conflicting = [ArkKnownTransaction {
        transaction_id: request.transaction_id,
        signed_transaction_sha256: "ff".repeat(32),
    }];
    assert_eq!(
        engine
            .next_broadcast_request(&bytes, "http://127.0.0.1:3002/api", 410, &conflicting,)
            .expect_err("same txid with other witness bytes must fail")
            .code,
        "swp_external_effect_conflict"
    );
}

#[test]
fn ark_exit_rejects_incomplete_unsafe_and_secret_bearing_packages() {
    let fixture = Fixture::from_json();

    let mut incomplete = fixture.package();
    let mut transaction = parse_exit_transaction(&incomplete);
    transaction
        .set_input_witness(1, Vec::new())
        .expect("clear fee-child witness");
    incomplete.exit.signed_transactions[0].signed_transaction =
        encode_hex(&transaction.serialize(true).expect("incomplete transaction"));
    assert_eq!(prepare_error(&fixture, &incomplete), "swp_ark_exit_unsafe");

    let mut expired = fixture.package();
    expired.exit.signed_transactions[0].latest_safe_broadcast_height = "399".into();
    assert_eq!(prepare_error(&fixture, &expired), "swp_ark_exit_unsafe");

    let mut secret = fixture.package();
    let mut transaction = parse_exit_transaction(&secret);
    let mut witness = transaction.inputs[0].witness.clone();
    witness.insert(1, vec![7; 32]);
    transaction
        .set_input_witness(0, witness)
        .expect("insert condition secret");
    secret.exit.signed_transactions[0].signed_transaction =
        encode_hex(&transaction.serialize(true).expect("secret transaction"));
    assert_eq!(
        prepare_error(&fixture, &secret),
        "swp_secret_material_forbidden"
    );

    let mut value = serde_json::to_value(fixture.package()).expect("Ark package JSON");
    value["exit"]["fee_key"] = Value::String("11".repeat(32));
    let bytes = canonical_json(&value).expect("canonical secret package");
    let binding = fixture.binding(&bytes);
    let input = fixture.input(&binding);
    assert_eq!(
        ArkClientEngine::prepare(&bytes, &input)
            .expect_err("fee key must fail")
            .code,
        "swp_secret_material_forbidden"
    );
}

#[test]
fn ark_exit_parser_rejects_duplicates_unknowns_and_changed_commitments() {
    let fixture = Fixture::from_json();
    let package = fixture.package();
    let bytes = canonical_json(&package).expect("canonical Ark package");
    let binding = fixture.binding(&bytes);
    let input = fixture.input(&binding);
    let duplicate = bytes
        .strip_suffix(b"}")
        .expect("package object terminator")
        .iter()
        .copied()
        .chain(
            b",\"schema\":\"openagents.mkt-swp.exit.v1\"}"
                .iter()
                .copied(),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        ArkClientEngine::prepare(&duplicate, &input)
            .expect_err("duplicate JSON member must fail")
            .code,
        "swp_ark_exit_unsafe"
    );

    let mut changed = package;
    changed.verification.vtxo_commitment_sha256 = "aa".repeat(32);
    assert_eq!(
        prepare_error(&fixture, &changed),
        "swp_exit_package_mismatch"
    );
}

fn prepare_error(fixture: &Fixture, package: &ArkExitPackage) -> &'static str {
    let bytes = canonical_json(package).expect("canonical mutated Ark package");
    let binding = fixture.binding(&bytes);
    let input = fixture.input(&binding);
    ArkClientEngine::prepare(&bytes, &input)
        .expect_err("mutated Ark package must fail")
        .code
}

fn parse_exit_transaction(package: &ArkExitPackage) -> Transaction {
    Transaction::parse(&decode_hex(
        &package.exit.signed_transactions[0].signed_transaction,
    ))
    .expect("Ark exit transaction")
}

struct Fixture {
    json: Value,
    descriptor: ArkOperatorDescriptor,
    policy: ArkOperatorPolicy,
    graph: ArkGraphMaterial,
    terms: ArkVtxoTerms,
    graph_sha256: [u8; 32],
}

impl Fixture {
    fn from_json() -> Self {
        let json: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/ark-rail-v1.json"
        ))
        .expect("Ark fixture JSON");
        let arkade = &json["arkade"];
        let descriptor =
            serde_json::from_value(arkade["descriptor"].clone()).expect("Ark descriptor fixture");
        let policy = serde_json::from_value(arkade["policy"].clone()).expect("Ark policy fixture");
        let anchor = ArkOutpoint::parse(
            arkade["anchor"]["outpoint"]
                .as_str()
                .expect("anchor outpoint"),
        )
        .expect("canonical anchor");
        let selected =
            ArkOutpoint::parse(arkade["vtxo"]["outpoint"].as_str().expect("VTXO outpoint"))
                .expect("canonical VTXO");
        let signed_transactions = arkade["signed_vtxo_graph"]
            .as_array()
            .expect("signed graph")
            .iter()
            .map(|value| value.as_str().expect("signed graph hex").to_owned())
            .collect::<Vec<_>>();
        let graph = ArkGraphMaterial {
            signed_transactions,
            observed_outputs: vec![ArkObservedOutput {
                outpoint: anchor.clone(),
                output: TransactionOutput {
                    value_sat: decimal(arkade["anchor"]["amount"].as_str().expect("anchor amount")),
                    script_pubkey: decode_hex(
                        arkade["anchor"]["script_pubkey"]
                            .as_str()
                            .expect("anchor script"),
                    ),
                },
            }],
        };
        let vtxo = &arkade["vtxo"];
        let terms = ArkVtxoTerms {
            asset_id: arkade["asset_id"].as_str().expect("asset ID").to_owned(),
            input_vtxo_ids: vec![anchor.clone()],
            output_vtxo_id: selected,
            amount_sat: decimal(vtxo["amount"].as_str().expect("VTXO amount")),
            owner_pubkey: vtxo["owner_pubkey"]
                .as_str()
                .expect("owner pubkey")
                .to_owned(),
            payment_hash: hex_32(vtxo["payment_hash"].as_str().expect("payment hash")),
            claim_script: decode_hex(vtxo["claim_script"].as_str().expect("claim script")),
            claim_control_block: decode_hex(
                vtxo["claim_control_block"]
                    .as_str()
                    .expect("claim control block"),
            ),
            refund_script: decode_hex(vtxo["refund_script"].as_str().expect("refund script")),
            refund_control_block: decode_hex(
                vtxo["refund_control_block"]
                    .as_str()
                    .expect("refund control block"),
            ),
            claim_path_sha256: hex_32(
                vtxo["claim_path_sha256"]
                    .as_str()
                    .expect("claim path digest"),
            ),
            refund_path_sha256: hex_32(
                vtxo["refund_path_sha256"]
                    .as_str()
                    .expect("refund path digest"),
            ),
            expiry_domain: vtxo["expiry"]["domain"]
                .as_str()
                .expect("expiry domain")
                .to_owned(),
            expiry_value: decimal(vtxo["expiry"]["value"].as_str().expect("expiry value")),
            unilateral_exit_domain: vtxo["unilateral_exit_delay"]["domain"]
                .as_str()
                .expect("exit delay domain")
                .to_owned(),
            unilateral_exit_delay: decimal(
                vtxo["unilateral_exit_delay"]["value"]
                    .as_str()
                    .expect("exit delay"),
            ),
            anchor_outpoint: anchor,
        };
        let graph_sha256 = hex_32(
            arkade["signed_vtxo_graph_sha256"]
                .as_str()
                .expect("graph digest"),
        );
        Self {
            json,
            descriptor,
            policy,
            graph,
            terms,
            graph_sha256,
        }
    }

    fn package(&self) -> ArkExitPackage {
        let signed_graph = Transaction::parse(&decode_hex(&self.graph.signed_transactions[0]))
            .expect("signed graph transaction");
        let graph_transaction_id = signed_graph.txid().expect("signed graph transaction ID");
        let selected_output = signed_graph.outputs[0].clone();
        let fee_output = signed_graph.outputs[1].clone();
        let owner_secret = SecretKey::from_byte_array([2; 32]).expect("owner fixture secret");
        let secp = Secp256k1::new();
        let owner_keypair = Keypair::from_secret_key(&secp, &owner_secret);
        let mut exit = Transaction::new(
            2,
            vec![
                TransactionInput {
                    previous_txid: consensus_txid(graph_transaction_id),
                    previous_output: 0,
                    script_sig: Vec::new(),
                    sequence: 10,
                    witness: Vec::new(),
                },
                TransactionInput {
                    previous_txid: consensus_txid(graph_transaction_id),
                    previous_output: 1,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                },
            ],
            vec![TransactionOutput {
                value_sat: 108_000,
                script_pubkey: fee_output.script_pubkey.clone(),
            }],
            0,
        );
        let prevouts = [selected_output, fee_output.clone()];
        let refund_sighash = taproot_script_spend_sighash(
            &exit,
            &prevouts,
            0,
            &self.terms.refund_script,
            &self.terms.refund_control_block,
        )
        .expect("refund sighash");
        let refund_signature = secp.sign_schnorr_no_aux_rand(&refund_sighash, &owner_keypair);
        let fee_sighash =
            taproot_key_spend_sighash(&exit, &prevouts, 1).expect("fee-child sighash");
        let fee_signature = secp.sign_schnorr_no_aux_rand(&fee_sighash, &owner_keypair);
        exit.set_input_witness(
            0,
            vec![
                refund_signature.as_ref().to_vec(),
                self.terms.refund_script.clone(),
                self.terms.refund_control_block.clone(),
            ],
        )
        .expect("refund witness");
        exit.set_input_witness(1, vec![fee_signature.as_ref().to_vec()])
            .expect("fee witness");
        let exit_raw = exit.serialize(true).expect("signed exit bytes");
        let exit_id = encode_hex(&exit.txid().expect("exit transaction ID"));
        ArkExitPackage {
            schema: "openagents.mkt-swp.exit.v1".into(),
            profile: "mkt-swp".into(),
            profile_version: 1,
            order_id: "66".repeat(32),
            swap_contract_ids: vec!["44".repeat(32), "55".repeat(32)],
            contract_sha256: "33".repeat(32),
            participant_role: "requester".into(),
            leg_id: "source".into(),
            network_id: self.descriptor.network_id.as_str().to_owned(),
            asset_id: self.terms.asset_id.clone(),
            effect_id: "77".repeat(32),
            funding: ArkExitFunding {
                vtxo_id: self.terms.output_vtxo_id.canonical(),
                input_vtxo_ids: self
                    .terms
                    .input_vtxo_ids
                    .iter()
                    .map(ArkOutpoint::canonical)
                    .collect(),
                anchor_outpoint: self.terms.anchor_outpoint.canonical(),
                signed_vtxo_graph: self.graph.signed_transactions.clone(),
                signed_vtxo_graph_sha256: encode_hex(&self.graph_sha256),
                amount: self.terms.amount_sat.to_string(),
                owner_pubkey: self.terms.owner_pubkey.clone(),
            },
            exit: ArkExitPlan {
                mode: "presigned".into(),
                fee_funding_mode: "prefunded_presigned".into(),
                path: "refund".into(),
                fee_child_outpoints: vec![format!("{}:1", encode_hex(&graph_transaction_id))],
                signed_transactions: vec![ArkSignedExitTransaction {
                    transaction_id: exit_id,
                    signed_transaction: encode_hex(&exit_raw),
                    parent_transaction_id: None,
                    earliest_broadcast_height: "410".into(),
                    latest_safe_broadcast_height: "480".into(),
                }],
                final_destination_script_pubkey: encode_hex(&fee_output.script_pubkey),
                fee_policy: ArkExitFeePolicy {
                    target_blocks: "2".into(),
                    maximum_total_fee: "2000".into(),
                    bump_mode: "replacement_forbidden".into(),
                },
            },
            verification: ArkExitVerification {
                network_id: self.descriptor.network_id.as_str().to_owned(),
                asset_id: self.terms.asset_id.clone(),
                protocol_family: self.descriptor.protocol_family,
                protocol_version: self.descriptor.protocol_version.clone(),
                operator_identity_sha256: self
                    .descriptor
                    .identity_hex()
                    .expect("operator identity"),
                operator_policy_sha256: self.descriptor.operator_policy_sha256.clone(),
                vtxo_commitment_sha256: encode_hex(
                    &ark_vtxo_commitment_sha256(&self.terms).expect("VTXO commitment"),
                ),
                payment_hash: encode_hex(&self.terms.payment_hash),
                claim_path_sha256: encode_hex(&self.terms.claim_path_sha256),
                refund_path_sha256: encode_hex(&self.terms.refund_path_sha256),
                expiry: ArkDomainValue {
                    domain: self.terms.expiry_domain.clone(),
                    value: self.terms.expiry_value.to_string(),
                },
                unilateral_exit_delay: ArkDomainValue {
                    domain: self.terms.unilateral_exit_domain.clone(),
                    value: self.terms.unilateral_exit_delay.to_string(),
                },
            },
            secret_commitments: ArkSecretCommitments {
                payment_hash: encode_hex(&self.terms.payment_hash),
                preimage_recovery_ref: None,
            },
            broadcast: ArkBroadcastPolicy {
                mode: "keyless_esplora_sequence".into(),
                esplora_urls: vec!["http://127.0.0.1:3002/api".into()],
                minimum_agreeing_sources: 1,
            },
        }
    }

    fn binding(&self, package_bytes: &[u8]) -> ArkContractBinding {
        ArkContractBinding {
            order_id: "66".repeat(32),
            swap_contract_ids: ["44".repeat(32), "55".repeat(32)],
            contract_sha256: "33".repeat(32),
            participant_role: "requester".into(),
            leg_id: "source".into(),
            effect_id: "77".repeat(32),
            exit_package_sha256: encode_hex(&sha256(package_bytes)),
        }
    }

    fn input<'a>(&'a self, binding: &'a ArkContractBinding) -> ArkExitVerificationInput<'a> {
        ArkExitVerificationInput {
            descriptor: &self.descriptor,
            policy: &self.policy,
            graph: &self.graph,
            terms: &self.terms,
            view: ArkVerificationView {
                block_height: BLOCK_HEIGHT,
                unix_time: 1_785_859_200,
            },
            signed_vtxo_graph_sha256: self.graph_sha256,
            contract: binding,
        }
    }
}

fn decimal(value: &str) -> u64 {
    value.parse().expect("fixture decimal")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex UTF-8"), 16)
                .expect("lowercase hex")
        })
        .collect()
}

fn hex_32(value: &str) -> [u8; 32] {
    decode_hex(value).try_into().expect("32-byte fixture hex")
}

fn consensus_txid(mut transaction_id: [u8; 32]) -> [u8; 32] {
    transaction_id.reverse();
    transaction_id
}
