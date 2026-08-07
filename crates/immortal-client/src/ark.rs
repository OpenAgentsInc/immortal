//! Verify-before-transfer and keyless recovery for MKT-SWP Ark legs.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use immortal_core::{
    ark::{
        ArkError, ArkGraphMaterial, ArkOperatorDescriptor, ArkOperatorPolicy, ArkOutpoint,
        ArkProtocolFamily, ArkVerificationView, ArkVtxoTerms, ark_vtxo_commitment_sha256,
        canonical_json, encode_hex, reject_ark_transaction_secrets, verify_ark_graph,
        verify_fully_signed_ark_transaction,
    },
    domain::parse_json_without_duplicate_members,
    mkt_swp_verify::{Transaction, TransactionOutput, sha256},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mkt_swp_client::validate_esplora_url;

const ARK_EXIT_SCHEMA: &str = "openagents.mkt-swp.exit.v1";
const ARK_PROFILE: &str = "mkt-swp";
const ARK_SNAPSHOT_SCHEMA: &str = "openagents.immortal.ark-client-snapshot.v1";
const MAX_ARK_EXIT_TRANSACTIONS: usize = 64;
const MAX_ARK_EXIT_BYTES: usize = 262_144;
const MAX_ARK_FEE_CHILDREN: usize = 64;
const MAX_ARK_ESPLORA_URLS: usize = 8;
const MAX_ARK_ARTIFACT_REF_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkClientError {
    pub code: &'static str,
    pub detail: String,
}

impl ArkClientError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ArkClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ArkClientError {}

impl From<ArkError> for ArkClientError {
    fn from(error: ArkError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitPackage {
    pub schema: String,
    pub profile: String,
    pub profile_version: u32,
    pub order_id: String,
    pub swap_contract_ids: Vec<String>,
    pub contract_sha256: String,
    pub participant_role: String,
    pub leg_id: String,
    pub network_id: String,
    pub asset_id: String,
    pub effect_id: String,
    pub funding: ArkExitFunding,
    pub exit: ArkExitPlan,
    pub verification: ArkExitVerification,
    pub secret_commitments: ArkSecretCommitments,
    pub broadcast: ArkBroadcastPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitFunding {
    pub vtxo_id: String,
    pub input_vtxo_ids: Vec<String>,
    pub anchor_outpoint: String,
    pub signed_vtxo_graph: Vec<String>,
    pub signed_vtxo_graph_sha256: String,
    pub amount: String,
    pub owner_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitPlan {
    pub mode: String,
    pub fee_funding_mode: String,
    pub path: String,
    pub fee_child_outpoints: Vec<String>,
    pub signed_transactions: Vec<ArkSignedExitTransaction>,
    pub final_destination_script_pubkey: String,
    pub fee_policy: ArkExitFeePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkSignedExitTransaction {
    pub transaction_id: String,
    pub signed_transaction: String,
    pub parent_transaction_id: Option<String>,
    pub earliest_broadcast_height: String,
    pub latest_safe_broadcast_height: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitFeePolicy {
    pub target_blocks: String,
    pub maximum_total_fee: String,
    pub bump_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitVerification {
    pub network_id: String,
    pub asset_id: String,
    pub protocol_family: ArkProtocolFamily,
    pub protocol_version: String,
    pub operator_identity_sha256: String,
    pub operator_policy_sha256: String,
    pub vtxo_commitment_sha256: String,
    pub payment_hash: String,
    pub claim_path_sha256: String,
    pub refund_path_sha256: String,
    pub expiry: ArkDomainValue,
    pub unilateral_exit_delay: ArkDomainValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkDomainValue {
    pub domain: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkSecretCommitments {
    pub payment_hash: String,
    pub preimage_recovery_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkBroadcastPolicy {
    pub mode: String,
    pub esplora_urls: Vec<String>,
    pub minimum_agreeing_sources: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkContractBinding {
    pub order_id: String,
    pub swap_contract_ids: [String; 2],
    pub contract_sha256: String,
    pub participant_role: String,
    pub leg_id: String,
    pub effect_id: String,
    pub exit_package_sha256: String,
}

pub struct ArkExitVerificationInput<'a> {
    pub descriptor: &'a ArkOperatorDescriptor,
    pub policy: &'a ArkOperatorPolicy,
    pub graph: &'a ArkGraphMaterial,
    pub terms: &'a ArkVtxoTerms,
    pub view: ArkVerificationView,
    pub signed_vtxo_graph_sha256: [u8; 32],
    pub contract: &'a ArkContractBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkPersistenceRequest {
    pub effect_id: String,
    pub artifact_sha256: String,
    pub canonical_package: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkPersistenceReceipt {
    pub artifact_sha256: String,
    pub artifact_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkExitTransactionSummary {
    pub transaction_id: String,
    pub signed_transaction_sha256: String,
    pub parent_transaction_id: Option<String>,
    pub earliest_broadcast_height: u64,
    pub latest_safe_broadcast_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkPersistedExit {
    pub artifact_sha256: String,
    pub artifact_ref: String,
    pub order_id: String,
    pub effect_id: String,
    pub vtxo_id: String,
    pub operator_identity_sha256: String,
    pub esplora_urls: Vec<String>,
    pub transactions: Vec<ArkExitTransactionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkFundingAuthorization {
    pub action: &'static str,
    pub order_id: String,
    pub effect_id: String,
    pub vtxo_id: String,
    pub operator_identity_sha256: String,
    pub exit_package_sha256: String,
    pub exit_package_artifact_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkKnownTransaction {
    pub transaction_id: String,
    pub signed_transaction_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkBroadcastRequest {
    pub effect_id: String,
    pub package_effect_id: String,
    pub transaction_id: String,
    pub signed_transaction_sha256: String,
    pub parent_transaction_id: Option<String>,
    pub method: String,
    pub url: String,
    pub content_type: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedArkExit {
    artifact_sha256: String,
    order_id: String,
    effect_id: String,
    vtxo_id: String,
    operator_identity_sha256: String,
    esplora_urls: Vec<String>,
    transactions: Vec<ArkExitTransactionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkClientEngine {
    prepared: Option<PreparedArkExit>,
    persisted: Option<ArkPersistedExit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArkClientSnapshot {
    schema: String,
    persisted: ArkPersistedExit,
}

impl ArkClientEngine {
    pub fn prepare(
        package_bytes: &[u8],
        input: &ArkExitVerificationInput<'_>,
    ) -> Result<(Self, ArkPersistenceRequest), ArkClientError> {
        let verified = verify_exit_package(package_bytes, input)?;
        let request = ArkPersistenceRequest {
            effect_id: verified.effect_id.clone(),
            artifact_sha256: verified.artifact_sha256.clone(),
            canonical_package: verified.canonical_package,
        };
        Ok((
            Self {
                prepared: Some(PreparedArkExit {
                    artifact_sha256: verified.artifact_sha256,
                    order_id: verified.order_id,
                    effect_id: verified.effect_id,
                    vtxo_id: verified.vtxo_id,
                    operator_identity_sha256: verified.operator_identity_sha256,
                    esplora_urls: verified.esplora_urls,
                    transactions: verified.transactions,
                }),
                persisted: None,
            },
            request,
        ))
    }

    pub fn confirm_persistence(
        mut self,
        receipt: ArkPersistenceReceipt,
    ) -> Result<Self, ArkClientError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            ArkClientError::new(
                "swp_exit_package_unusable",
                "Ark client has no verified package awaiting persistence",
            )
        })?;
        validate_artifact_ref(&receipt.artifact_ref)?;
        if receipt.artifact_sha256 != prepared.artifact_sha256 {
            return Err(ArkClientError::new(
                "swp_exit_package_unusable",
                "Ark persistence receipt differs from the verified package digest",
            ));
        }
        self.persisted = Some(ArkPersistedExit {
            artifact_sha256: prepared.artifact_sha256,
            artifact_ref: receipt.artifact_ref,
            order_id: prepared.order_id,
            effect_id: prepared.effect_id,
            vtxo_id: prepared.vtxo_id,
            operator_identity_sha256: prepared.operator_identity_sha256,
            esplora_urls: prepared.esplora_urls,
            transactions: prepared.transactions,
        });
        Ok(self)
    }

    pub fn authorize_transfer(&self) -> Result<ArkFundingAuthorization, ArkClientError> {
        let persisted = self.persisted.as_ref().ok_or_else(|| {
            ArkClientError::new(
                "swp_funding_not_authorized",
                "Ark transfer requires a verified external persistence receipt",
            )
        })?;
        Ok(ArkFundingAuthorization {
            action: "ark_transfer",
            order_id: persisted.order_id.clone(),
            effect_id: persisted.effect_id.clone(),
            vtxo_id: persisted.vtxo_id.clone(),
            operator_identity_sha256: persisted.operator_identity_sha256.clone(),
            exit_package_sha256: persisted.artifact_sha256.clone(),
            exit_package_artifact_ref: persisted.artifact_ref.clone(),
        })
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, ArkClientError> {
        let persisted = self.persisted.clone().ok_or_else(|| {
            ArkClientError::new(
                "swp_exit_package_unusable",
                "Ark client snapshot requires a persistence receipt",
            )
        })?;
        canonical_json(&ArkClientSnapshot {
            schema: ARK_SNAPSHOT_SCHEMA.to_owned(),
            persisted,
        })
        .map_err(ArkClientError::from)
    }

    pub fn restore(snapshot: &[u8]) -> Result<Self, ArkClientError> {
        let text = core::str::from_utf8(snapshot)
            .map_err(|_| ArkClientError::new("swp_unresolved_loss", "Ark snapshot is not UTF-8"))?;
        let value = parse_json_without_duplicate_members(text, "Ark client snapshot")
            .map_err(|detail| ArkClientError::new("swp_unresolved_loss", detail))?;
        let snapshot: ArkClientSnapshot = serde_json::from_value(value).map_err(|error| {
            ArkClientError::new(
                "swp_unresolved_loss",
                format!("Ark snapshot shape is invalid: {error}"),
            )
        })?;
        if snapshot.schema != ARK_SNAPSHOT_SCHEMA {
            return Err(ArkClientError::new(
                "swp_unsupported_version",
                "Ark snapshot schema is unsupported",
            ));
        }
        validate_persisted_exit(&snapshot.persisted)?;
        Ok(Self {
            prepared: None,
            persisted: Some(snapshot.persisted),
        })
    }

    pub fn persisted_exit(&self) -> Option<&ArkPersistedExit> {
        self.persisted.as_ref()
    }

    pub fn next_broadcast_request(
        &self,
        package_bytes: &[u8],
        esplora_url: &str,
        block_height: u64,
        known_transactions: &[ArkKnownTransaction],
    ) -> Result<Option<ArkBroadcastRequest>, ArkClientError> {
        let persisted = self.persisted.as_ref().ok_or_else(|| {
            ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark recovery requires a persisted exit package",
            )
        })?;
        let (package, canonical) = parse_package(package_bytes)?;
        if package_bytes != canonical
            || encode_hex(&sha256(&canonical)) != persisted.artifact_sha256
        {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "loaded Ark package differs from its persisted canonical digest",
            ));
        }
        if package.effect_id != persisted.effect_id
            || package.order_id != persisted.order_id
            || package.funding.vtxo_id != persisted.vtxo_id
            || package.exit.signed_transactions.len() != persisted.transactions.len()
        {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "loaded Ark package differs from its persisted recovery identity",
            ));
        }
        let endpoint = validate_esplora_url(esplora_url)
            .map_err(|error| ArkClientError::new(error.code, error.detail))?;
        if !persisted.esplora_urls.iter().any(|value| value == endpoint) {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Esplora endpoint is absent from the persisted Ark package",
            ));
        }
        let known = validate_known_transactions(known_transactions)?;
        for (index, (transaction, summary)) in package
            .exit
            .signed_transactions
            .iter()
            .zip(&persisted.transactions)
            .enumerate()
        {
            let digest = encode_hex(&sha256(&decode_lower_hex(
                &transaction.signed_transaction,
                "Ark signed exit transaction",
            )?));
            if transaction.transaction_id != summary.transaction_id
                || transaction.parent_transaction_id != summary.parent_transaction_id
                || digest != summary.signed_transaction_sha256
            {
                return Err(ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "loaded Ark transaction differs from its persisted summary",
                ));
            }
            if let Some(known_digest) = known.get(&transaction.transaction_id) {
                if known_digest != &digest {
                    return Err(ArkClientError::new(
                        "swp_external_effect_conflict",
                        "Ark transaction ID is already known with different witness bytes",
                    ));
                }
                continue;
            }
            if index > 0 {
                let parent = transaction
                    .parent_transaction_id
                    .as_deref()
                    .ok_or_else(|| {
                        ArkClientError::new(
                            "swp_ark_exit_unsafe",
                            "Ark exit transaction is missing its parent",
                        )
                    })?;
                if !known.contains_key(parent) {
                    return Ok(None);
                }
            }
            if block_height > summary.latest_safe_broadcast_height {
                return Err(ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "Ark exit transaction passed its latest safe broadcast height",
                ));
            }
            if block_height < summary.earliest_broadcast_height {
                return Ok(None);
            }
            let effect_id = encode_hex(&sha256(
                format!(
                    "ark-exit:{}:{index}:{}",
                    persisted.effect_id, transaction.transaction_id
                )
                .as_bytes(),
            ));
            return Ok(Some(ArkBroadcastRequest {
                effect_id,
                package_effect_id: persisted.effect_id.clone(),
                transaction_id: transaction.transaction_id.clone(),
                signed_transaction_sha256: digest,
                parent_transaction_id: transaction.parent_transaction_id.clone(),
                method: "POST".to_owned(),
                url: format!("{endpoint}/tx"),
                content_type: "text/plain".to_owned(),
                body: transaction.signed_transaction.clone(),
            }));
        }
        Ok(None)
    }
}

struct VerifiedExitPackage {
    artifact_sha256: String,
    canonical_package: Vec<u8>,
    order_id: String,
    effect_id: String,
    vtxo_id: String,
    operator_identity_sha256: String,
    esplora_urls: Vec<String>,
    transactions: Vec<ArkExitTransactionSummary>,
}

fn verify_exit_package(
    package_bytes: &[u8],
    input: &ArkExitVerificationInput<'_>,
) -> Result<VerifiedExitPackage, ArkClientError> {
    let (package, canonical) = parse_package(package_bytes)?;
    let artifact_sha256 = encode_hex(&sha256(&canonical));
    validate_contract_binding(&package, input.contract, &artifact_sha256)?;
    let verified_graph = verify_ark_graph(
        input.descriptor,
        input.policy,
        input.graph,
        input.terms,
        input.view,
        input.signed_vtxo_graph_sha256,
    )?;
    validate_package_binding(&package, input, &verified_graph.signed_vtxo_graph_sha256)?;
    let transactions = verify_exit_transactions(&package, input)?;
    Ok(VerifiedExitPackage {
        artifact_sha256,
        canonical_package: canonical,
        order_id: package.order_id,
        effect_id: package.effect_id,
        vtxo_id: package.funding.vtxo_id,
        operator_identity_sha256: package.verification.operator_identity_sha256,
        esplora_urls: package.broadcast.esplora_urls,
        transactions,
    })
}

fn parse_package(package_bytes: &[u8]) -> Result<(ArkExitPackage, Vec<u8>), ArkClientError> {
    if package_bytes.is_empty() || package_bytes.len() > MAX_ARK_EXIT_BYTES {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark exit package is empty or exceeds its byte bound",
        ));
    }
    let text = core::str::from_utf8(package_bytes)
        .map_err(|_| ArkClientError::new("swp_ark_exit_unsafe", "Ark exit package is not UTF-8"))?;
    let value = parse_json_without_duplicate_members(text, "Ark exit package")
        .map_err(|detail| ArkClientError::new("swp_ark_exit_unsafe", detail))?;
    reject_forbidden_members(&value)?;
    let package: ArkExitPackage = serde_json::from_value(value).map_err(|error| {
        ArkClientError::new(
            "swp_ark_exit_unsafe",
            format!("Ark exit package shape is invalid: {error}"),
        )
    })?;
    let canonical = canonical_json(&package)?;
    Ok((package, canonical))
}

fn validate_contract_binding(
    package: &ArkExitPackage,
    binding: &ArkContractBinding,
    artifact_sha256: &str,
) -> Result<(), ArkClientError> {
    for value in [
        &binding.order_id,
        &binding.swap_contract_ids[0],
        &binding.swap_contract_ids[1],
        &binding.contract_sha256,
        &binding.effect_id,
        &binding.exit_package_sha256,
    ] {
        require_lower_hex(value, 64, "Ark contract binding")?;
    }
    if !matches!(binding.participant_role.as_str(), "requester" | "provider")
        || !matches!(binding.leg_id.as_str(), "source" | "destination")
        || package.schema != ARK_EXIT_SCHEMA
        || package.profile != ARK_PROFILE
        || package.profile_version != 1
        || package.order_id != binding.order_id
        || package.swap_contract_ids != binding.swap_contract_ids
        || package.contract_sha256 != binding.contract_sha256
        || package.participant_role != binding.participant_role
        || package.leg_id != binding.leg_id
        || package.effect_id != binding.effect_id
        || artifact_sha256 != binding.exit_package_sha256
    {
        return Err(ArkClientError::new(
            "swp_exit_package_mismatch",
            "Ark exit package differs from its bilateral Contract binding",
        ));
    }
    Ok(())
}

fn validate_package_binding(
    package: &ArkExitPackage,
    input: &ArkExitVerificationInput<'_>,
    graph_sha256: &[u8; 32],
) -> Result<(), ArkClientError> {
    let terms = input.terms;
    let descriptor = input.descriptor;
    let graph_digest = encode_hex(graph_sha256);
    let input_ids = terms
        .input_vtxo_ids
        .iter()
        .map(ArkOutpoint::canonical)
        .collect::<Vec<_>>();
    if package.network_id != descriptor.network_id.as_str()
        || package.asset_id != terms.asset_id
        || package.funding.vtxo_id != terms.output_vtxo_id.canonical()
        || package.funding.input_vtxo_ids != input_ids
        || package.funding.anchor_outpoint != terms.anchor_outpoint.canonical()
        || package.funding.signed_vtxo_graph != input.graph.signed_transactions
        || package.funding.signed_vtxo_graph_sha256 != graph_digest
        || package.funding.amount != terms.amount_sat.to_string()
        || package.funding.owner_pubkey != terms.owner_pubkey
        || package.verification.network_id != descriptor.network_id.as_str()
        || package.verification.asset_id != terms.asset_id
        || package.verification.protocol_family != descriptor.protocol_family
        || package.verification.protocol_version != descriptor.protocol_version
        || package.verification.operator_identity_sha256 != descriptor.identity_hex()?
        || package.verification.operator_policy_sha256 != descriptor.operator_policy_sha256
        || package.verification.vtxo_commitment_sha256
            != encode_hex(&ark_vtxo_commitment_sha256(terms)?)
        || package.verification.payment_hash != encode_hex(&terms.payment_hash)
        || package.verification.claim_path_sha256 != encode_hex(&terms.claim_path_sha256)
        || package.verification.refund_path_sha256 != encode_hex(&terms.refund_path_sha256)
        || package.verification.expiry.domain != terms.expiry_domain
        || package.verification.expiry.value != terms.expiry_value.to_string()
        || package.verification.unilateral_exit_delay.domain != terms.unilateral_exit_domain
        || package.verification.unilateral_exit_delay.value
            != terms.unilateral_exit_delay.to_string()
        || package.secret_commitments.payment_hash != encode_hex(&terms.payment_hash)
        || package.secret_commitments.preimage_recovery_ref.is_some()
    {
        return Err(ArkClientError::new(
            "swp_exit_package_mismatch",
            "Ark exit package differs from its verified VTXO or operator binding",
        ));
    }
    if package.exit.mode != "presigned"
        || package.exit.fee_funding_mode != "prefunded_presigned"
        || !matches!(
            package.exit.path.as_str(),
            "claim" | "refund" | "unilateral_exit"
        )
        || package.broadcast.mode != "keyless_esplora_sequence"
        || package.broadcast.minimum_agreeing_sources == 0
        || usize::try_from(package.broadcast.minimum_agreeing_sources).unwrap_or(usize::MAX)
            > package.broadcast.esplora_urls.len()
        || package.broadcast.esplora_urls.is_empty()
        || package.broadcast.esplora_urls.len() > MAX_ARK_ESPLORA_URLS
        || package.exit.fee_policy.target_blocks != "2"
        || !matches!(
            package.exit.fee_policy.bump_mode.as_str(),
            "cpfp" | "replacement_forbidden"
        )
    {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark exit mode, path, fee policy, or broadcast policy is unsupported",
        ));
    }
    let mut endpoints = BTreeSet::new();
    for endpoint in &package.broadcast.esplora_urls {
        let normalized = validate_esplora_url(endpoint)
            .map_err(|error| ArkClientError::new(error.code, error.detail))?;
        if normalized != *endpoint || !endpoints.insert(endpoint) {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark Esplora endpoints are duplicated or non-canonical",
            ));
        }
    }
    require_lower_hex(
        &package.exit.final_destination_script_pubkey,
        package.exit.final_destination_script_pubkey.len(),
        "Ark final destination script",
    )?;
    if package.exit.final_destination_script_pubkey.is_empty() {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark final destination script is empty",
        ));
    }
    Ok(())
}

fn verify_exit_transactions(
    package: &ArkExitPackage,
    input: &ArkExitVerificationInput<'_>,
) -> Result<Vec<ArkExitTransactionSummary>, ArkClientError> {
    if package.exit.signed_transactions.is_empty()
        || package.exit.signed_transactions.len() > MAX_ARK_EXIT_TRANSACTIONS
        || package.exit.fee_child_outpoints.is_empty()
        || package.exit.fee_child_outpoints.len() > MAX_ARK_FEE_CHILDREN
    {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark exit transaction or fee-child count is outside its bound",
        ));
    }
    let maximum_fee = parse_decimal(
        &package.exit.fee_policy.maximum_total_fee,
        "Ark maximum total fee",
    )?;
    let selected = input.terms.output_vtxo_id.clone();
    let fee_children = parse_unique_outpoints(&package.exit.fee_child_outpoints)?;
    if fee_children.contains(&selected) {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "selected Ark VTXO cannot also be a fee child",
        ));
    }
    let mut outputs = graph_output_map(input.graph)?;
    let mut consumed_fee_children = BTreeSet::new();
    let mut total_fee = 0_u64;
    let mut decoded_bytes = 0_usize;
    let mut previous_transaction_id = None;
    let mut summaries = Vec::with_capacity(package.exit.signed_transactions.len());
    let final_script = decode_lower_hex(
        &package.exit.final_destination_script_pubkey,
        "Ark final destination script",
    )?;
    for (index, signed) in package.exit.signed_transactions.iter().enumerate() {
        require_lower_hex(&signed.transaction_id, 64, "Ark exit transaction ID")?;
        if signed.parent_transaction_id != previous_transaction_id {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit transaction parent ordering is invalid",
            ));
        }
        let raw = decode_lower_hex(&signed.signed_transaction, "Ark signed exit transaction")?;
        decoded_bytes = decoded_bytes.checked_add(raw.len()).ok_or_else(|| {
            ArkClientError::new("swp_ark_exit_unsafe", "Ark exit byte count overflowed")
        })?;
        if decoded_bytes > MAX_ARK_EXIT_BYTES {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark signed exit transactions exceed their byte bound",
            ));
        }
        let transaction = Transaction::parse(&raw).map_err(|_| {
            ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark signed exit transaction encoding is invalid",
            )
        })?;
        reject_ark_transaction_secrets(&transaction)?;
        let transaction_id = transaction.txid().map_err(|_| {
            ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark signed exit transaction ID cannot be computed",
            )
        })?;
        if encode_hex(&transaction_id) != signed.transaction_id {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark signed exit transaction ID differs from its bytes",
            ));
        }
        let earliest = parse_decimal(
            &signed.earliest_broadcast_height,
            "Ark earliest broadcast height",
        )?;
        let latest = parse_decimal(
            &signed.latest_safe_broadcast_height,
            "Ark latest safe broadcast height",
        )?;
        if earliest > latest || input.view.block_height > latest {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit transaction has no safe broadcast window",
            ));
        }
        if input.terms.expiry_domain == "block_height" && latest >= input.terms.expiry_value {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit transaction latest-safe height does not precede VTXO expiry",
            ));
        }
        let mut prevouts = Vec::with_capacity(transaction.inputs.len());
        let mut spends_selected = false;
        let mut spends_parent = index == 0;
        for transaction_input in &transaction.inputs {
            let outpoint = input_outpoint(
                transaction_input.previous_txid,
                transaction_input.previous_output,
            );
            if outpoint == selected {
                spends_selected = true;
                validate_selected_witness(
                    &package.exit.path,
                    transaction_input.witness.as_slice(),
                    input.terms,
                )?;
            }
            let spends_previous = previous_transaction_id
                .as_ref()
                .is_some_and(|parent| encode_hex(&outpoint.transaction_id()) == *parent);
            if spends_previous {
                spends_parent = true;
            }
            if outpoint != selected && !fee_children.contains(&outpoint) && !spends_previous {
                return Err(ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "Ark exit input is not the selected VTXO, a committed fee child, or its parent",
                ));
            }
            if fee_children.contains(&outpoint) && !consumed_fee_children.insert(outpoint.clone()) {
                return Err(ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "Ark fee child is consumed more than once",
                ));
            }
            let prevout = outputs.remove(&outpoint).ok_or_else(|| {
                ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "Ark exit input is absent, already spent, or outside the verified graph",
                )
            })?;
            prevouts.push(prevout);
        }
        if transaction
            .inputs
            .iter()
            .any(|transaction_input| !transaction_input.script_sig.is_empty())
        {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark Taproot exit input carries a non-empty scriptSig",
            ));
        }
        if (index == 0 && !spends_selected) || !spends_parent {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit does not begin at the selected VTXO or continue from its parent",
            ));
        }
        verify_fully_signed_ark_transaction(&transaction, &prevouts)?;
        let input_value = prevouts.iter().try_fold(0_u64, |total, output| {
            total.checked_add(output.value_sat).ok_or_else(|| {
                ArkClientError::new("swp_ark_exit_unsafe", "Ark exit input amount overflowed")
            })
        })?;
        let output_value = transaction
            .outputs
            .iter()
            .try_fold(0_u64, |total, output| {
                total.checked_add(output.value_sat).ok_or_else(|| {
                    ArkClientError::new("swp_ark_exit_unsafe", "Ark exit output amount overflowed")
                })
            })?;
        let transaction_fee = input_value.checked_sub(output_value).ok_or_else(|| {
            ArkClientError::new("swp_ark_exit_unsafe", "Ark exit transaction creates value")
        })?;
        total_fee = total_fee
            .checked_add(transaction_fee)
            .ok_or_else(|| ArkClientError::new("swp_ark_exit_unsafe", "Ark exit fee overflowed"))?;
        if total_fee > maximum_fee {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit total fee exceeds its committed maximum",
            ));
        }
        for (output_index, output) in transaction.outputs.iter().enumerate() {
            let output_index = u32::try_from(output_index).map_err(|_| {
                ArkClientError::new("swp_ark_exit_unsafe", "Ark exit output index exceeds u32")
            })?;
            outputs.insert(
                ArkOutpoint::from_parts(transaction_id, output_index),
                output.clone(),
            );
        }
        if index + 1 == package.exit.signed_transactions.len()
            && transaction
                .outputs
                .iter()
                .filter(|output| output.script_pubkey == final_script)
                .count()
                != 1
        {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark exit final transaction does not have one exact destination output",
            ));
        }
        let digest = encode_hex(&sha256(&raw));
        summaries.push(ArkExitTransactionSummary {
            transaction_id: signed.transaction_id.clone(),
            signed_transaction_sha256: digest,
            parent_transaction_id: signed.parent_transaction_id.clone(),
            earliest_broadcast_height: earliest,
            latest_safe_broadcast_height: latest,
        });
        previous_transaction_id = Some(signed.transaction_id.clone());
    }
    if consumed_fee_children != fee_children {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark exit does not consume every committed fee child",
        ));
    }
    Ok(summaries)
}

fn graph_output_map(
    graph: &ArkGraphMaterial,
) -> Result<BTreeMap<ArkOutpoint, TransactionOutput>, ArkClientError> {
    let mut outputs = BTreeMap::new();
    for observed in &graph.observed_outputs {
        if outputs
            .insert(observed.outpoint.clone(), observed.output.clone())
            .is_some()
        {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark graph has duplicate observed outputs",
            ));
        }
    }
    let mut transactions = Vec::with_capacity(graph.signed_transactions.len());
    for raw_hex in &graph.signed_transactions {
        let raw = decode_lower_hex(raw_hex, "Ark graph transaction")?;
        let transaction = Transaction::parse(&raw).map_err(|_| {
            ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark graph transaction cannot be decoded for exit verification",
            )
        })?;
        let transaction_id = transaction.txid().map_err(|_| {
            ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark graph transaction ID cannot be computed",
            )
        })?;
        for (output_index, output) in transaction.outputs.iter().cloned().enumerate() {
            let output_index = u32::try_from(output_index).map_err(|_| {
                ArkClientError::new("swp_ark_exit_unsafe", "Ark graph output index exceeds u32")
            })?;
            if outputs
                .insert(
                    ArkOutpoint::from_parts(transaction_id, output_index),
                    output,
                )
                .is_some()
            {
                return Err(ArkClientError::new(
                    "swp_ark_exit_unsafe",
                    "Ark graph output identity collides",
                ));
            }
        }
        transactions.push(transaction);
    }
    for transaction in transactions {
        for input in transaction.inputs {
            outputs.remove(&input_outpoint(input.previous_txid, input.previous_output));
        }
    }
    Ok(outputs)
}

fn validate_selected_witness(
    path: &str,
    witness: &[Vec<u8>],
    terms: &ArkVtxoTerms,
) -> Result<(), ArkClientError> {
    let matches = match (path, witness) {
        ("claim", [signature]) => signature.len() == 64,
        ("refund" | "unilateral_exit", [signature, script, control_block]) => {
            signature.len() == 64
                && script == &terms.refund_script
                && control_block == &terms.refund_control_block
        }
        _ => false,
    };
    if !matches {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "Ark selected VTXO witness does not match the secret-free recovery path",
        ));
    }
    Ok(())
}

fn parse_unique_outpoints(values: &[String]) -> Result<BTreeSet<ArkOutpoint>, ArkClientError> {
    let mut outpoints = BTreeSet::new();
    for value in values {
        let outpoint = ArkOutpoint::parse(value)?;
        if !outpoints.insert(outpoint) {
            return Err(ArkClientError::new(
                "swp_ark_exit_unsafe",
                "Ark fee child outpoints are duplicated",
            ));
        }
    }
    Ok(outpoints)
}

fn input_outpoint(mut transaction_id: [u8; 32], output_index: u32) -> ArkOutpoint {
    transaction_id.reverse();
    ArkOutpoint::from_parts(transaction_id, output_index)
}

fn validate_known_transactions(
    known_transactions: &[ArkKnownTransaction],
) -> Result<BTreeMap<String, String>, ArkClientError> {
    if known_transactions.len() > MAX_ARK_EXIT_TRANSACTIONS {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            "known Ark transaction set exceeds its bound",
        ));
    }
    let mut known = BTreeMap::new();
    for transaction in known_transactions {
        require_lower_hex(&transaction.transaction_id, 64, "known Ark transaction ID")?;
        require_lower_hex(
            &transaction.signed_transaction_sha256,
            64,
            "known Ark transaction digest",
        )?;
        if let Some(previous) = known.insert(
            transaction.transaction_id.clone(),
            transaction.signed_transaction_sha256.clone(),
        ) && previous != transaction.signed_transaction_sha256
        {
            return Err(ArkClientError::new(
                "swp_external_effect_conflict",
                "known Ark transaction ID has conflicting byte digests",
            ));
        }
    }
    Ok(known)
}

fn validate_persisted_exit(persisted: &ArkPersistedExit) -> Result<(), ArkClientError> {
    require_lower_hex(
        &persisted.artifact_sha256,
        64,
        "persisted Ark artifact digest",
    )?;
    require_lower_hex(&persisted.order_id, 64, "persisted Ark order ID")?;
    require_lower_hex(&persisted.effect_id, 64, "persisted Ark effect ID")?;
    require_lower_hex(
        &persisted.operator_identity_sha256,
        64,
        "persisted Ark operator identity",
    )?;
    ArkOutpoint::parse(&persisted.vtxo_id)?;
    validate_artifact_ref(&persisted.artifact_ref)?;
    if persisted.transactions.is_empty()
        || persisted.transactions.len() > MAX_ARK_EXIT_TRANSACTIONS
        || persisted.esplora_urls.is_empty()
        || persisted.esplora_urls.len() > MAX_ARK_ESPLORA_URLS
    {
        return Err(ArkClientError::new(
            "swp_unresolved_loss",
            "persisted Ark recovery state exceeds its bounds",
        ));
    }
    let mut endpoints = BTreeSet::new();
    for endpoint in &persisted.esplora_urls {
        let normalized = validate_esplora_url(endpoint)
            .map_err(|error| ArkClientError::new(error.code, error.detail))?;
        if normalized != *endpoint || !endpoints.insert(endpoint) {
            return Err(ArkClientError::new(
                "swp_unresolved_loss",
                "persisted Ark endpoint set is invalid",
            ));
        }
    }
    for (index, transaction) in persisted.transactions.iter().enumerate() {
        require_lower_hex(
            &transaction.transaction_id,
            64,
            "persisted Ark transaction ID",
        )?;
        require_lower_hex(
            &transaction.signed_transaction_sha256,
            64,
            "persisted Ark transaction digest",
        )?;
        let expected_parent = index
            .checked_sub(1)
            .and_then(|parent| persisted.transactions.get(parent))
            .map(|parent| parent.transaction_id.as_str());
        if transaction.parent_transaction_id.as_deref() != expected_parent
            || transaction.earliest_broadcast_height > transaction.latest_safe_broadcast_height
        {
            return Err(ArkClientError::new(
                "swp_unresolved_loss",
                "persisted Ark transaction sequence is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_artifact_ref(value: &str) -> Result<(), ArkClientError> {
    if value.is_empty()
        || value.len() > MAX_ARK_ARTIFACT_REF_BYTES
        || value.contains("://")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(ArkClientError::new(
            "swp_exit_package_unusable",
            "Ark artifact reference is not a bounded opaque local reference",
        ));
    }
    Ok(())
}

fn reject_forbidden_members(value: &Value) -> Result<(), ArkClientError> {
    match value {
        Value::Object(members) => {
            for (name, value) in members {
                let normalized = name
                    .bytes()
                    .filter(|byte| byte.is_ascii_alphanumeric())
                    .map(|byte| byte.to_ascii_lowercase())
                    .collect::<Vec<_>>();
                let forbidden = matches!(
                    normalized.as_slice(),
                    b"feekey"
                        | b"spendkey"
                        | b"vtxokey"
                        | b"privatekey"
                        | b"secretnonce"
                        | b"preimage"
                        | b"paymentpreimage"
                        | b"seed"
                        | b"macaroon"
                        | b"bearertoken"
                        | b"operatortoken"
                );
                if forbidden {
                    return Err(ArkClientError::new(
                        "swp_secret_material_forbidden",
                        format!("Ark package contains forbidden custody member {name:?}"),
                    ));
                }
                reject_forbidden_members(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_forbidden_members(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_decimal(value: &str, subject: &str) -> Result<u64, ArkClientError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            format!("{subject} is not a canonical decimal string"),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| ArkClientError::new("swp_ark_exit_unsafe", format!("{subject} exceeds u64")))
}

fn require_lower_hex(value: &str, length: usize, subject: &str) -> Result<(), ArkClientError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            format!("{subject} is not lowercase hex"),
        ));
    }
    Ok(())
}

fn decode_lower_hex(value: &str, subject: &str) -> Result<Vec<u8>, ArkClientError> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArkClientError::new(
            "swp_ark_exit_unsafe",
            format!("{subject} is not lowercase hex"),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                ArkClientError::new("swp_ark_exit_unsafe", format!("{subject} is invalid"))
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                ArkClientError::new("swp_ark_exit_unsafe", format!("{subject} is invalid"))
            })?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
