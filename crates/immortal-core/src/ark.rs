//! Bounded, family-explicit verification primitives for MKT-SWP Ark legs.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey, schnorr::Signature as SchnorrSignature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mkt_swp_verify::{
    SwapLeafCondition, Transaction, TransactionOutput, parse_swap_leaf_script, sha256,
    taproot_key_spend_sighash, validate_taproot_refund_witness, verify_control_block,
};

pub const MAX_ARK_INPUT_VTXOS: usize = 32;
pub const MAX_ARK_GRAPH_TRANSACTIONS: usize = 64;
pub const MAX_ARK_PARENT_EDGES: usize = 32;
pub const MAX_ARK_GRAPH_BYTES: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkError {
    OperatorMismatch(&'static str),
    GraphInvalid(&'static str),
    VtxoInvalid(&'static str),
    ExitUnsafe(&'static str),
    InvalidPair(&'static str),
    SecretMaterialForbidden(&'static str),
}

impl ArkError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OperatorMismatch(_) => "swp_ark_operator_mismatch",
            Self::GraphInvalid(_) => "swp_ark_graph_invalid",
            Self::VtxoInvalid(_) => "swp_ark_vtxo_invalid",
            Self::ExitUnsafe(_) => "swp_ark_exit_unsafe",
            Self::InvalidPair(_) => "swp_invalid_pair",
            Self::SecretMaterialForbidden(_) => "swp_secret_material_forbidden",
        }
    }
}

impl fmt::Display for ArkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, detail) = match self {
            Self::OperatorMismatch(detail) => ("Ark operator mismatch", detail),
            Self::GraphInvalid(detail) => ("invalid Ark graph", detail),
            Self::VtxoInvalid(detail) => ("invalid Ark VTXO", detail),
            Self::ExitUnsafe(detail) => ("unsafe Ark exit", detail),
            Self::InvalidPair(detail) => ("invalid Ark pair", detail),
            Self::SecretMaterialForbidden(detail) => ("forbidden Ark custody material", detail),
        };
        write!(formatter, "{label}: {detail}")
    }
}

impl std::error::Error for ArkError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArkProtocolFamily {
    Arkade,
    Bark,
}

impl ArkProtocolFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arkade => "arkade",
            Self::Bark => "bark",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArkNetworkId(String);

impl ArkNetworkId {
    pub fn parse(value: &str) -> Result<Self, ArkError> {
        let Some(reference) = value.strip_prefix("bip122:") else {
            return Err(ArkError::OperatorMismatch("network identifier prefix"));
        };
        if !is_lower_hex(reference, 32) {
            return Err(ArkError::OperatorMismatch("network identifier shape"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ArkNetworkId {
    type Error = ArkError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ArkNetworkId> for String {
    fn from(value: ArkNetworkId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkOperatorKeys {
    pub signer_pubkey: Option<String>,
    pub forfeit_pubkey: Option<String>,
    pub server_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkOperatorDescriptor {
    pub network_id: ArkNetworkId,
    pub protocol_family: ArkProtocolFamily,
    pub protocol_version: String,
    pub operator_keys: ArkOperatorKeys,
    pub operator_policy_sha256: String,
}

impl ArkOperatorDescriptor {
    pub fn validate(&self) -> Result<(), ArkError> {
        if !is_protocol_version(&self.protocol_version) {
            return Err(ArkError::OperatorMismatch("protocol version"));
        }
        if !is_lower_hex(&self.operator_policy_sha256, 64) {
            return Err(ArkError::OperatorMismatch("operator policy digest"));
        }
        for key in [
            self.operator_keys.signer_pubkey.as_deref(),
            self.operator_keys.forfeit_pubkey.as_deref(),
            self.operator_keys.server_pubkey.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            parse_public_key(key)?;
        }
        let family_keys_match = match self.protocol_family {
            ArkProtocolFamily::Arkade => {
                self.operator_keys.signer_pubkey.is_some()
                    && self.operator_keys.forfeit_pubkey.is_some()
                    && self.operator_keys.server_pubkey.is_none()
            }
            ArkProtocolFamily::Bark => {
                self.operator_keys.signer_pubkey.is_none()
                    && self.operator_keys.forfeit_pubkey.is_none()
                    && self.operator_keys.server_pubkey.is_some()
            }
        };
        if !family_keys_match {
            return Err(ArkError::OperatorMismatch("family key set"));
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> Result<[u8; 32], ArkError> {
        self.validate()?;
        canonical_sha256(self)
    }

    pub fn identity_hex(&self) -> Result<String, ArkError> {
        Ok(encode_hex(&self.identity_sha256()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkAssetId {
    network_id: ArkNetworkId,
    protocol_family: ArkProtocolFamily,
    operator_identity_sha256: String,
}

impl ArkAssetId {
    pub fn parse(value: &str) -> Result<Self, ArkError> {
        let Some(value) = value.strip_prefix("swp:1:") else {
            return Err(ArkError::VtxoInvalid("asset identifier prefix"));
        };
        let Some((network_id, rail)) = value.split_once(":btc:ark:") else {
            return Err(ArkError::VtxoInvalid("asset identifier rail"));
        };
        let Some((family, identity)) = rail.split_once(':') else {
            return Err(ArkError::VtxoInvalid("asset identifier family"));
        };
        if identity.contains(':') || !is_lower_hex(identity, 64) {
            return Err(ArkError::VtxoInvalid("asset operator identity"));
        }
        let protocol_family = match family {
            "arkade" => ArkProtocolFamily::Arkade,
            "bark" => ArkProtocolFamily::Bark,
            _ => return Err(ArkError::VtxoInvalid("asset protocol family")),
        };
        Ok(Self {
            network_id: ArkNetworkId::parse(network_id)?,
            protocol_family,
            operator_identity_sha256: identity.to_owned(),
        })
    }

    pub fn network_id(&self) -> &ArkNetworkId {
        &self.network_id
    }

    pub const fn protocol_family(&self) -> ArkProtocolFamily {
        self.protocol_family
    }

    pub fn operator_identity_sha256(&self) -> &str {
        &self.operator_identity_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArkOutpoint {
    transaction_id: [u8; 32],
    output_index: u32,
}

impl ArkOutpoint {
    pub fn parse(value: &str) -> Result<Self, ArkError> {
        let Some((transaction_id, output_index)) = value.split_once(':') else {
            return Err(ArkError::GraphInvalid("outpoint shape"));
        };
        if output_index.is_empty()
            || (output_index.len() > 1 && output_index.starts_with('0'))
            || !output_index.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ArkError::GraphInvalid("outpoint output index"));
        }
        let output_index = output_index
            .parse::<u32>()
            .map_err(|_| ArkError::GraphInvalid("outpoint output index"))?;
        Ok(Self {
            transaction_id: parse_lower_hex_32(transaction_id)
                .map_err(|_| ArkError::GraphInvalid("outpoint transaction ID"))?,
            output_index,
        })
    }

    pub fn from_parts(transaction_id: [u8; 32], output_index: u32) -> Self {
        Self {
            transaction_id,
            output_index,
        }
    }

    pub fn transaction_id(&self) -> [u8; 32] {
        self.transaction_id
    }

    pub const fn output_index(&self) -> u32 {
        self.output_index
    }

    pub fn canonical(&self) -> String {
        format!("{}:{}", encode_hex(&self.transaction_id), self.output_index)
    }

    fn from_input(transaction_id_consensus: [u8; 32], output_index: u32) -> Self {
        let mut transaction_id = transaction_id_consensus;
        transaction_id.reverse();
        Self::from_parts(transaction_id, output_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkOperatorPolicy {
    pub network_id: String,
    pub protocol_family: ArkProtocolFamily,
    pub protocol_version: String,
    pub minimum_vtxo_amount: String,
    pub maximum_vtxo_amount: String,
    pub maximum_input_vtxos: u32,
    pub maximum_graph_transactions: u32,
    pub maximum_parent_edges: u32,
    pub maximum_graph_bytes: u32,
    pub maximum_transaction_weight: u64,
    pub expiry_domain: String,
    pub minimum_expiry_delta: String,
    pub unilateral_exit_domain: String,
    pub unilateral_exit_delay: String,
    pub checkpoint_script_sha256: String,
    pub fee_rule_sha256: String,
}

impl ArkOperatorPolicy {
    pub fn validate(&self) -> Result<(), ArkError> {
        let network = ArkNetworkId::parse(&self.network_id)?;
        if network.as_str() != self.network_id
            || !is_protocol_version(&self.protocol_version)
            || !matches!(self.expiry_domain.as_str(), "block_height" | "unix_time")
            || !matches!(self.unilateral_exit_domain.as_str(), "blocks" | "seconds")
            || !is_lower_hex(&self.checkpoint_script_sha256, 64)
            || !is_lower_hex(&self.fee_rule_sha256, 64)
        {
            return Err(ArkError::OperatorMismatch("operator policy grammar"));
        }
        let minimum = parse_decimal(&self.minimum_vtxo_amount, false)
            .map_err(|_| ArkError::OperatorMismatch("minimum VTXO amount"))?;
        let maximum = parse_decimal(&self.maximum_vtxo_amount, false)
            .map_err(|_| ArkError::OperatorMismatch("maximum VTXO amount"))?;
        parse_decimal(&self.minimum_expiry_delta, false)
            .map_err(|_| ArkError::OperatorMismatch("minimum expiry delta"))?;
        parse_decimal(&self.unilateral_exit_delay, false)
            .map_err(|_| ArkError::OperatorMismatch("unilateral exit delay"))?;
        if minimum > maximum
            || self.maximum_input_vtxos == 0
            || usize::try_from(self.maximum_input_vtxos).ok() > Some(MAX_ARK_INPUT_VTXOS)
            || self.maximum_graph_transactions == 0
            || usize::try_from(self.maximum_graph_transactions).ok()
                > Some(MAX_ARK_GRAPH_TRANSACTIONS)
            || self.maximum_parent_edges == 0
            || usize::try_from(self.maximum_parent_edges).ok() > Some(MAX_ARK_PARENT_EDGES)
            || self.maximum_graph_bytes == 0
            || usize::try_from(self.maximum_graph_bytes).ok() > Some(MAX_ARK_GRAPH_BYTES)
            || self.maximum_transaction_weight == 0
        {
            return Err(ArkError::OperatorMismatch("operator policy bounds"));
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, ArkError> {
        self.validate()?;
        Ok(encode_hex(&canonical_sha256(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkObservedOutput {
    pub outpoint: ArkOutpoint,
    pub output: TransactionOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkGraphMaterial {
    pub signed_transactions: Vec<String>,
    pub observed_outputs: Vec<ArkObservedOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkVtxoTerms {
    pub asset_id: String,
    pub input_vtxo_ids: Vec<ArkOutpoint>,
    pub output_vtxo_id: ArkOutpoint,
    pub amount_sat: u64,
    pub owner_pubkey: String,
    pub payment_hash: [u8; 32],
    pub claim_script: Vec<u8>,
    pub claim_control_block: Vec<u8>,
    pub refund_script: Vec<u8>,
    pub refund_control_block: Vec<u8>,
    pub claim_path_sha256: [u8; 32],
    pub refund_path_sha256: [u8; 32],
    pub expiry_domain: String,
    pub expiry_value: u64,
    pub unilateral_exit_domain: String,
    pub unilateral_exit_delay: u64,
    pub anchor_outpoint: ArkOutpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArkVerificationView {
    pub block_height: u64,
    pub unix_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArkGraph {
    pub signed_vtxo_graph_sha256: [u8; 32],
    pub transaction_ids: Vec<[u8; 32]>,
    pub selected_output: TransactionOutput,
    pub selected_script_pubkey: Vec<u8>,
    pub parent_edges: usize,
}

pub fn verify_operator_binding(
    descriptor: &ArkOperatorDescriptor,
    policy: &ArkOperatorPolicy,
    expected_identity_sha256: &str,
) -> Result<(), ArkError> {
    descriptor.validate()?;
    policy.validate()?;
    if policy.network_id != descriptor.network_id.as_str()
        || policy.protocol_family != descriptor.protocol_family
        || policy.protocol_version != descriptor.protocol_version
        || policy.digest_hex()? != descriptor.operator_policy_sha256
        || descriptor.identity_hex()? != expected_identity_sha256
    {
        return Err(ArkError::OperatorMismatch("descriptor or policy binding"));
    }
    Ok(())
}

pub fn verify_ark_pair(input_asset_id: &str, output_asset_id: &str) -> Result<(), ArkError> {
    let input_ark = ArkAssetId::parse(input_asset_id).ok();
    let output_ark = ArkAssetId::parse(output_asset_id).ok();
    match (input_ark, output_ark) {
        (Some(_), Some(_)) => Err(ArkError::InvalidPair("Ark-to-Ark is unsupported in v1")),
        (Some(ark), None) => verify_chain_peer(output_asset_id, &ark),
        (None, Some(ark)) => verify_chain_peer(input_asset_id, &ark),
        (None, None) => Ok(()),
    }
}

fn verify_chain_peer(peer: &str, ark: &ArkAssetId) -> Result<(), ArkError> {
    let expected = format!("swp:1:{}:btc:chain", ark.network_id().as_str());
    let lightning = format!("swp:1:{}:btc:lightning", ark.network_id().as_str());
    if peer != expected && peer != lightning {
        return Err(ArkError::InvalidPair("Ark pair network or rail"));
    }
    Ok(())
}

pub fn verify_ark_graph(
    descriptor: &ArkOperatorDescriptor,
    policy: &ArkOperatorPolicy,
    material: &ArkGraphMaterial,
    terms: &ArkVtxoTerms,
    view: ArkVerificationView,
    expected_graph_sha256: [u8; 32],
) -> Result<VerifiedArkGraph, ArkError> {
    let asset = ArkAssetId::parse(&terms.asset_id)?;
    verify_operator_binding(descriptor, policy, asset.operator_identity_sha256())?;
    if asset.network_id() != &descriptor.network_id
        || asset.protocol_family() != descriptor.protocol_family
    {
        return Err(ArkError::OperatorMismatch("asset operator binding"));
    }
    verify_graph_bounds(policy, material, terms)?;

    let mut decoded_bytes = 0_usize;
    let mut transactions = Vec::with_capacity(material.signed_transactions.len());
    let mut transaction_ids = Vec::with_capacity(material.signed_transactions.len());
    let mut transaction_by_id = BTreeMap::new();
    for raw_hex in &material.signed_transactions {
        let raw =
            decode_lower_hex(raw_hex).map_err(|_| ArkError::GraphInvalid("transaction hex"))?;
        decoded_bytes = decoded_bytes
            .checked_add(raw.len())
            .ok_or(ArkError::GraphInvalid("decoded graph byte length"))?;
        let transaction =
            Transaction::parse(&raw).map_err(|_| ArkError::GraphInvalid("transaction encoding"))?;
        if transaction
            .weight()
            .map_err(|_| ArkError::GraphInvalid("transaction weight"))?
            > policy.maximum_transaction_weight
        {
            return Err(ArkError::GraphInvalid("transaction weight"));
        }
        let transaction_id = transaction
            .txid()
            .map_err(|_| ArkError::GraphInvalid("transaction ID"))?;
        if transaction_by_id
            .insert(transaction_id, transactions.len())
            .is_some()
        {
            return Err(ArkError::GraphInvalid("duplicate transaction ID"));
        }
        transaction_ids.push(transaction_id);
        transactions.push(transaction);
    }
    if decoded_bytes > usize::try_from(policy.maximum_graph_bytes).unwrap_or(usize::MAX)
        || decoded_bytes > MAX_ARK_GRAPH_BYTES
    {
        return Err(ArkError::GraphInvalid("decoded graph byte length"));
    }

    let graph_digest = canonical_sha256(&material.signed_transactions)?;
    if graph_digest != expected_graph_sha256 {
        return Err(ArkError::GraphInvalid("signed graph digest"));
    }

    let observed = observed_output_map(&material.observed_outputs)?;
    let allowed_roots = terms
        .input_vtxo_ids
        .iter()
        .chain(core::iter::once(&terms.anchor_outpoint))
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed
        .keys()
        .any(|outpoint| !allowed_roots.contains(outpoint))
        || allowed_roots
            .iter()
            .any(|outpoint| !observed.contains_key(outpoint))
    {
        return Err(ArkError::GraphInvalid("observed root set"));
    }

    let mut spent = BTreeSet::new();
    let mut spent_roots = BTreeSet::new();
    let mut dependencies = vec![BTreeSet::new(); transactions.len()];
    let mut children = vec![BTreeSet::new(); transactions.len()];
    for (transaction_index, transaction) in transactions.iter().enumerate() {
        let mut prevouts = Vec::with_capacity(transaction.inputs.len());
        for input in &transaction.inputs {
            let outpoint = ArkOutpoint::from_input(input.previous_txid, input.previous_output);
            if !spent.insert(outpoint.clone()) {
                return Err(ArkError::GraphInvalid("duplicate graph spend"));
            }
            if let Some(parent_index) = transaction_by_id.get(&outpoint.transaction_id()) {
                let parent = transactions
                    .get(*parent_index)
                    .ok_or(ArkError::GraphInvalid("parent transaction"))?;
                let output_index = usize::try_from(outpoint.output_index())
                    .map_err(|_| ArkError::GraphInvalid("parent output index"))?;
                let output = parent
                    .outputs
                    .get(output_index)
                    .ok_or(ArkError::GraphInvalid("parent output index"))?;
                dependencies[transaction_index].insert(*parent_index);
                children[*parent_index].insert(transaction_index);
                prevouts.push(output.clone());
            } else {
                let output = observed
                    .get(&outpoint)
                    .ok_or(ArkError::GraphInvalid("unobserved graph root"))?;
                spent_roots.insert(outpoint);
                prevouts.push((*output).clone());
            }
        }
        verify_transaction_signatures(transaction, &prevouts)
            .map_err(|_| ArkError::GraphInvalid("transaction signature"))?;
    }
    if spent_roots != allowed_roots {
        return Err(ArkError::GraphInvalid("unconsumed observed graph root"));
    }
    reject_graph_cycles(&dependencies)?;
    verify_family_topology(descriptor.protocol_family, &dependencies, &children)?;

    let selected_transaction_index = transaction_by_id
        .get(&terms.output_vtxo_id.transaction_id())
        .copied()
        .ok_or(ArkError::VtxoInvalid("selected transaction is absent"))?;
    let selected_transaction = transactions
        .get(selected_transaction_index)
        .ok_or(ArkError::VtxoInvalid("selected transaction"))?;
    if !graph_is_connected(selected_transaction_index, &dependencies, &children)? {
        return Err(ArkError::GraphInvalid("disconnected transaction"));
    }
    if spent.contains(&terms.output_vtxo_id) {
        return Err(ArkError::VtxoInvalid("selected VTXO is already spent"));
    }
    let selected_output_index = usize::try_from(terms.output_vtxo_id.output_index())
        .map_err(|_| ArkError::VtxoInvalid("selected output index"))?;
    let selected_output = selected_transaction
        .outputs
        .get(selected_output_index)
        .cloned()
        .ok_or(ArkError::VtxoInvalid("selected output index"))?;
    let parent_edges = maximum_parent_depth(selected_transaction_index, &dependencies)?;
    if parent_edges == 0
        || parent_edges > usize::try_from(policy.maximum_parent_edges).unwrap_or(usize::MAX)
        || parent_edges > MAX_ARK_PARENT_EDGES
    {
        return Err(ArkError::GraphInvalid("selected parent edge bound"));
    }
    verify_vtxo_terms(policy, terms, view, &selected_output)?;

    Ok(VerifiedArkGraph {
        signed_vtxo_graph_sha256: graph_digest,
        transaction_ids,
        selected_script_pubkey: selected_output.script_pubkey.clone(),
        selected_output,
        parent_edges,
    })
}

fn graph_is_connected(
    selected: usize,
    dependencies: &[BTreeSet<usize>],
    children: &[BTreeSet<usize>],
) -> Result<bool, ArkError> {
    let mut pending = vec![selected];
    let mut connected = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if !connected.insert(index) {
            continue;
        }
        let parents = dependencies
            .get(index)
            .ok_or(ArkError::GraphInvalid("dependency connection index"))?;
        let descendants = children
            .get(index)
            .ok_or(ArkError::GraphInvalid("child connection index"))?;
        pending.extend(parents);
        pending.extend(descendants);
    }
    Ok(connected.len() == dependencies.len() && dependencies.len() == children.len())
}

fn verify_graph_bounds(
    policy: &ArkOperatorPolicy,
    material: &ArkGraphMaterial,
    terms: &ArkVtxoTerms,
) -> Result<(), ArkError> {
    let input_limit = usize::try_from(policy.maximum_input_vtxos).unwrap_or(usize::MAX);
    let graph_limit = usize::try_from(policy.maximum_graph_transactions).unwrap_or(usize::MAX);
    if terms.input_vtxo_ids.is_empty()
        || terms.input_vtxo_ids.len() > input_limit
        || terms.input_vtxo_ids.len() > MAX_ARK_INPUT_VTXOS
        || material.signed_transactions.is_empty()
        || material.signed_transactions.len() > graph_limit
        || material.signed_transactions.len() > MAX_ARK_GRAPH_TRANSACTIONS
    {
        return Err(ArkError::GraphInvalid("graph object count"));
    }
    let input_set = terms.input_vtxo_ids.iter().collect::<BTreeSet<_>>();
    if input_set.len() != terms.input_vtxo_ids.len()
        || terms
            .input_vtxo_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArkError::GraphInvalid("input VTXO ordering"));
    }
    Ok(())
}

fn observed_output_map(
    outputs: &[ArkObservedOutput],
) -> Result<BTreeMap<ArkOutpoint, &TransactionOutput>, ArkError> {
    let mut observed = BTreeMap::new();
    for output in outputs {
        if observed
            .insert(output.outpoint.clone(), &output.output)
            .is_some()
        {
            return Err(ArkError::GraphInvalid("duplicate observed output"));
        }
    }
    Ok(observed)
}

fn reject_graph_cycles(dependencies: &[BTreeSet<usize>]) -> Result<(), ArkError> {
    fn visit(
        index: usize,
        dependencies: &[BTreeSet<usize>],
        visiting: &mut BTreeSet<usize>,
        visited: &mut BTreeSet<usize>,
    ) -> Result<(), ArkError> {
        if visited.contains(&index) {
            return Ok(());
        }
        if !visiting.insert(index) {
            return Err(ArkError::GraphInvalid("graph cycle"));
        }
        let parents = dependencies
            .get(index)
            .ok_or(ArkError::GraphInvalid("dependency index"))?;
        for parent in parents {
            visit(*parent, dependencies, visiting, visited)?;
        }
        visiting.remove(&index);
        visited.insert(index);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for index in 0..dependencies.len() {
        visit(index, dependencies, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn verify_family_topology(
    family: ArkProtocolFamily,
    dependencies: &[BTreeSet<usize>],
    children: &[BTreeSet<usize>],
) -> Result<(), ArkError> {
    if family == ArkProtocolFamily::Bark
        && (dependencies.iter().any(|parents| parents.len() > 1)
            || children.iter().any(|children| children.len() > 1))
    {
        return Err(ArkError::GraphInvalid("Bark transaction-chain topology"));
    }
    Ok(())
}

fn maximum_parent_depth(index: usize, dependencies: &[BTreeSet<usize>]) -> Result<usize, ArkError> {
    fn depth(
        index: usize,
        dependencies: &[BTreeSet<usize>],
        memo: &mut BTreeMap<usize, usize>,
    ) -> Result<usize, ArkError> {
        if let Some(depth) = memo.get(&index) {
            return Ok(*depth);
        }
        let parents = dependencies
            .get(index)
            .ok_or(ArkError::GraphInvalid("dependency depth index"))?;
        let depth = if parents.is_empty() {
            1
        } else {
            parents
                .iter()
                .try_fold(0_usize, |maximum, parent| {
                    depth(*parent, dependencies, memo).map(|value| maximum.max(value))
                })?
                .checked_add(1)
                .ok_or(ArkError::GraphInvalid("dependency depth"))?
        };
        memo.insert(index, depth);
        Ok(depth)
    }
    depth(index, dependencies, &mut BTreeMap::new())
}

fn verify_transaction_signatures(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
) -> Result<(), ArkError> {
    if transaction.inputs.len() != prevouts.len() {
        return Err(ArkError::GraphInvalid("transaction prevout count"));
    }
    for (input_index, input) in transaction.inputs.iter().enumerate() {
        let (signature, signing_key, sighash) = match input.witness.as_slice() {
            [signature] if signature.len() == 64 => {
                let output = prevouts
                    .get(input_index)
                    .ok_or(ArkError::GraphInvalid("signature prevout"))?;
                let signing_key = p2tr_output_key(&output.script_pubkey)?;
                let sighash = taproot_key_spend_sighash(transaction, prevouts, input_index)
                    .map_err(|_| ArkError::GraphInvalid("key-spend sighash"))?;
                (signature.as_slice(), signing_key, sighash)
            }
            [signature, script, _control_block] if signature.len() == 64 => {
                let validated = validate_taproot_refund_witness(
                    transaction,
                    prevouts,
                    input_index,
                    script,
                    _control_block,
                )
                .map_err(|_| ArkError::GraphInvalid("script-spend witness"))?;
                (
                    signature.as_slice(),
                    validated.signing_key,
                    validated.sighash,
                )
            }
            _ => return Err(ArkError::GraphInvalid("signed witness shape")),
        };
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| ArkError::GraphInvalid("Schnorr signature length"))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &SchnorrSignature::from_byte_array(signature),
                &sighash,
                &signing_key,
            )
            .map_err(|_| ArkError::GraphInvalid("Schnorr signature"))?;
    }
    Ok(())
}

fn verify_vtxo_terms(
    policy: &ArkOperatorPolicy,
    terms: &ArkVtxoTerms,
    view: ArkVerificationView,
    output: &TransactionOutput,
) -> Result<(), ArkError> {
    let minimum = parse_decimal(&policy.minimum_vtxo_amount, false)
        .map_err(|_| ArkError::OperatorMismatch("minimum VTXO amount"))?;
    let maximum = parse_decimal(&policy.maximum_vtxo_amount, false)
        .map_err(|_| ArkError::OperatorMismatch("maximum VTXO amount"))?;
    if terms.amount_sat < minimum
        || terms.amount_sat > maximum
        || output.value_sat != terms.amount_sat
    {
        return Err(ArkError::VtxoInvalid("VTXO amount"));
    }
    if terms.claim_path_sha256 != sha256(&terms.claim_script)
        || terms.refund_path_sha256 != sha256(&terms.refund_script)
    {
        return Err(ArkError::VtxoInvalid("VTXO path digest"));
    }
    let owner = parse_public_key(&terms.owner_pubkey)?;
    let claim = parse_swap_leaf_script(&terms.claim_script)
        .map_err(|_| ArkError::VtxoInvalid("claim tapscript"))?;
    let refund = parse_swap_leaf_script(&terms.refund_script)
        .map_err(|_| ArkError::VtxoInvalid("refund tapscript"))?;
    if claim.signing_key != owner
        || refund.signing_key != owner
        || claim.condition != SwapLeafCondition::Hashlock(terms.payment_hash)
    {
        return Err(ArkError::VtxoInvalid("VTXO owner or payment hash"));
    }
    let delay_matches = match (&refund.condition, terms.unilateral_exit_domain.as_str()) {
        (SwapLeafCondition::Csv(value), "blocks") => {
            u64::from(*value) == terms.unilateral_exit_delay
        }
        (SwapLeafCondition::Cltv(value), "seconds") => u64::from(*value) == terms.expiry_value,
        _ => false,
    };
    if !delay_matches
        || terms.expiry_domain != policy.expiry_domain
        || terms.unilateral_exit_domain != policy.unilateral_exit_domain
        || terms.unilateral_exit_delay
            != parse_decimal(&policy.unilateral_exit_delay, false)
                .map_err(|_| ArkError::OperatorMismatch("unilateral exit delay"))?
    {
        return Err(ArkError::VtxoInvalid("VTXO expiry or exit delay"));
    }
    let minimum_expiry_delta = parse_decimal(&policy.minimum_expiry_delta, false)
        .map_err(|_| ArkError::OperatorMismatch("minimum expiry delta"))?;
    let current = match terms.expiry_domain.as_str() {
        "block_height" => view.block_height,
        "unix_time" => view.unix_time,
        _ => return Err(ArkError::VtxoInvalid("VTXO expiry domain")),
    };
    if terms.expiry_value <= current
        || terms.expiry_value.saturating_sub(current) < minimum_expiry_delta
    {
        return Err(ArkError::VtxoInvalid("VTXO expiry"));
    }
    let output_key = p2tr_output_key(&output.script_pubkey)?;
    verify_control_block(&output_key, &terms.claim_script, &terms.claim_control_block)
        .map_err(|_| ArkError::VtxoInvalid("claim path commitment"))?;
    verify_control_block(
        &output_key,
        &terms.refund_script,
        &terms.refund_control_block,
    )
    .map_err(|_| ArkError::VtxoInvalid("refund path commitment"))?;
    Ok(())
}

pub fn ark_vtxo_commitment_sha256(terms: &ArkVtxoTerms) -> Result<[u8; 32], ArkError> {
    #[derive(Serialize)]
    struct DomainValue<'a> {
        domain: &'a str,
        value: String,
    }
    #[derive(Serialize)]
    struct Commitment<'a> {
        asset_id: &'a str,
        output_vtxo_id: String,
        amount: String,
        owner_pubkey: &'a str,
        payment_hash: String,
        claim_path_sha256: String,
        refund_path_sha256: String,
        expiry: DomainValue<'a>,
        unilateral_exit_delay: DomainValue<'a>,
        anchor_outpoint: String,
    }
    canonical_sha256(&Commitment {
        asset_id: &terms.asset_id,
        output_vtxo_id: terms.output_vtxo_id.canonical(),
        amount: terms.amount_sat.to_string(),
        owner_pubkey: &terms.owner_pubkey,
        payment_hash: encode_hex(&terms.payment_hash),
        claim_path_sha256: encode_hex(&terms.claim_path_sha256),
        refund_path_sha256: encode_hex(&terms.refund_path_sha256),
        expiry: DomainValue {
            domain: &terms.expiry_domain,
            value: terms.expiry_value.to_string(),
        },
        unilateral_exit_delay: DomainValue {
            domain: &terms.unilateral_exit_domain,
            value: terms.unilateral_exit_delay.to_string(),
        },
        anchor_outpoint: terms.anchor_outpoint.canonical(),
    })
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ArkError> {
    let value =
        serde_json::to_value(value).map_err(|_| ArkError::GraphInvalid("canonical JSON input"))?;
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<[u8; 32], ArkError> {
    Ok(sha256(&canonical_json(value)?))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), ArkError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ArkError::GraphInvalid("canonical JSON string"))?
                .as_bytes(),
        ),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(ArkError::GraphInvalid("non-integer canonical JSON number"));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut members = values.iter().collect::<Vec<_>>();
            members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, (name, value)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(name)
                        .map_err(|_| ArkError::GraphInvalid("canonical JSON member"))?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn parse_public_key(value: &str) -> Result<XOnlyPublicKey, ArkError> {
    let bytes =
        decode_lower_hex(value).map_err(|_| ArkError::OperatorMismatch("public key hex"))?;
    match bytes.len() {
        32 => XOnlyPublicKey::from_byte_array(
            bytes
                .try_into()
                .map_err(|_| ArkError::OperatorMismatch("x-only public key length"))?,
        )
        .map_err(|_| ArkError::OperatorMismatch("x-only public key")),
        33 if matches!(bytes.first(), Some(2 | 3)) => PublicKey::from_slice(&bytes)
            .map(|key| key.x_only_public_key().0)
            .map_err(|_| ArkError::OperatorMismatch("compressed public key")),
        _ => Err(ArkError::OperatorMismatch("public key shape")),
    }
}

fn p2tr_output_key(script_pubkey: &[u8]) -> Result<XOnlyPublicKey, ArkError> {
    let key = script_pubkey
        .strip_prefix(&[0x51, 0x20])
        .filter(|key| key.len() == 32)
        .ok_or(ArkError::VtxoInvalid("P2TR scriptPubKey"))?;
    XOnlyPublicKey::from_byte_array(
        key.try_into()
            .map_err(|_| ArkError::VtxoInvalid("P2TR output key length"))?,
    )
    .map_err(|_| ArkError::VtxoInvalid("P2TR output key"))
}

fn parse_decimal(value: &str, allow_zero: bool) -> Result<u64, ()> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    let value = value.parse::<u64>().map_err(|_| ())?;
    if !allow_zero && value == 0 {
        return Err(());
    }
    Ok(value)
}

fn is_protocol_version(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 32
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_lower_hex_32(value: &str) -> Result<[u8; 32], ()> {
    let bytes = decode_lower_hex(value)?;
    bytes.try_into().map_err(|_| ())
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(())?;
            let low = hex_nibble(pair[1]).ok_or(())?;
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

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{ArkError, graph_is_connected, reject_graph_cycles};
    use std::collections::BTreeSet;

    #[test]
    fn graph_cycle_is_rejected() {
        let dependencies = [BTreeSet::from([1]), BTreeSet::from([0])];
        assert_eq!(
            reject_graph_cycles(&dependencies),
            Err(ArkError::GraphInvalid("graph cycle"))
        );
    }

    #[test]
    fn disconnected_graph_is_rejected() {
        let dependencies = [BTreeSet::new(), BTreeSet::new()];
        let children = [BTreeSet::new(), BTreeSet::new()];
        assert_eq!(graph_is_connected(0, &dependencies, &children), Ok(false));
    }
}
