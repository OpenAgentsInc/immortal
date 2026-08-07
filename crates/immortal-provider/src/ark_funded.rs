//! Durable execution of externally signed Ark transfers.

use core::fmt;
use std::collections::BTreeSet;

use immortal_client::{
    ark::{ArkClientEngine, ArkFundingAuthorization},
    mkt_swp_client::provider_support::effect_id,
};
use immortal_core::{
    ark::{ArkAssetId, ArkOutpoint, canonical_json, encode_hex, reject_ark_transaction_secrets},
    mkt_swp_verify::{Transaction, sha256},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    arkd::{ArkdClient, ArkdError, ArkdVtxo},
    store::{
        ProviderStore, ProviderStoreError, PublicEffectRequest, PublicEffectResult,
        StoredPublicEffect,
    },
};

const MAX_CHECKPOINT_TRANSACTIONS: usize = 64;
const MAX_TRANSACTION_BYTES: usize = 1_000_000;
pub const MAX_ARK_TRANSFER_COMMAND_BYTES: usize = 4 * 1024 * 1024;
pub const ARK_TRANSFER_COMMAND_SCHEMA: &str = "openagents.immortal.ark-transfer-command.v1";

#[derive(Debug)]
pub enum ArkFundedError {
    Invalid(&'static str),
    Arkd(ArkdError),
    Store(ProviderStoreError),
}

impl fmt::Display for ArkFundedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "invalid funded Ark effect: {detail}"),
            Self::Arkd(error) => write!(formatter, "funded Ark effect failed at arkd: {error}"),
            Self::Store(error) => write!(formatter, "funded Ark effect storage failed: {error}"),
        }
    }
}

impl std::error::Error for ArkFundedError {}

impl From<ArkdError> for ArkFundedError {
    fn from(error: ArkdError) -> Self {
        Self::Arkd(error)
    }
}

impl From<ProviderStoreError> for ArkFundedError {
    fn from(error: ProviderStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkTransferMaterial {
    pub asset_id: String,
    pub input_vtxo_ids: Vec<String>,
    pub output_vtxo_id: String,
    pub amount_sat: u64,
    pub output_script_pubkey: String,
    pub signed_vtxo_graph_sha256: String,
    pub exit_package_sha256: String,
    pub signed_ark_transaction: String,
    pub final_ark_transaction_sha256: String,
    pub checkpoint_transactions: Vec<String>,
    pub final_checkpoint_transactions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkTransferReceipt {
    pub operator_identity_sha256: String,
    pub input_vtxo_ids: Vec<String>,
    pub output_vtxo_id: String,
    pub signed_vtxo_graph_sha256: String,
    pub exit_package_sha256: String,
    pub ark_transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArkTransferCommand {
    pub schema: String,
    pub session_id: String,
    pub leg_id: String,
    pub client_snapshot: Value,
    pub material: ArkTransferMaterial,
}

#[derive(Clone)]
pub struct ArkFundedRail {
    client: ArkdClient,
}

impl fmt::Debug for ArkFundedRail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArkFundedRail")
            .field(
                "operator_identity_sha256",
                &self.client.operator_identity_sha256(),
            )
            .finish()
    }
}

impl ArkFundedRail {
    pub fn new(client: ArkdClient) -> Self {
        Self { client }
    }

    pub fn asset_id(&self) -> String {
        format!(
            "swp:1:bip122:0f9188f13cb7b2c9e5c30f844f792506:btc:ark:arkade:{}",
            self.client.operator_identity_sha256()
        )
    }

    pub async fn execute_transfer(
        &self,
        store: &mut ProviderStore,
        session_id: &str,
        authorization: &ArkFundingAuthorization,
        material: &ArkTransferMaterial,
        now: u64,
    ) -> Result<ArkTransferReceipt, ArkFundedError> {
        let validated = self.validate_transfer(session_id, authorization, material)?;
        let request_sha256 = canonical_digest(material)?;
        let public_request = json!({
            "action":"ark_transfer",
            "asset_id":material.asset_id,
            "checkpoint_transaction_sha256":validated.checkpoint_transaction_sha256,
            "exit_package_sha256":material.exit_package_sha256,
            "final_ark_transaction_sha256":material.final_ark_transaction_sha256,
            "final_checkpoint_transaction_sha256":validated.final_checkpoint_transaction_sha256,
            "input_vtxo_ids":material.input_vtxo_ids,
            "operator_identity_sha256":self.client.operator_identity_sha256(),
            "order_id":authorization.order_id,
            "output_vtxo_id":material.output_vtxo_id,
            "signed_ark_transaction_sha256":validated.signed_ark_transaction_sha256,
            "signed_vtxo_graph_sha256":material.signed_vtxo_graph_sha256,
        });
        store
            .persist_effect_request(&PublicEffectRequest {
                effect_id: authorization.effect_id.clone(),
                session_id: session_id.to_owned(),
                operation: "ark_transfer".to_owned(),
                request_sha256: request_sha256.clone(),
                public_request,
                created_at: now,
            })
            .await?;
        if let Some(existing) = store.public_effect(&authorization.effect_id).await? {
            if existing.state == "applied" {
                return applied_receipt(existing);
            }
        }

        self.client.info().await?;
        match self.client.vtxo(&validated.output_vtxo).await {
            Ok(observed) => {
                verify_observed_vtxo(&observed, material)?;
                let receipt = self.receipt(material, &validated.output_vtxo);
                complete_transfer(store, authorization, request_sha256, &receipt, now).await?;
                return Ok(receipt);
            }
            Err(ArkdError::HttpStatus(404)) => {}
            Err(error) => return Err(error.into()),
        }

        let submission = self
            .client
            .submit_transaction(
                &material.signed_ark_transaction,
                &material.checkpoint_transactions,
            )
            .await?;
        if encode_hex(&sha256(&decode_lower_hex(
            &submission.final_ark_transaction,
            "final Ark transaction",
        )?)) != material.final_ark_transaction_sha256
            || submission.signed_checkpoint_transactions != material.final_checkpoint_transactions
        {
            return Err(ArkFundedError::Invalid(
                "arkd returned transaction bytes outside the contract-bound result",
            ));
        }
        self.client
            .finalize_transaction(
                &submission.ark_transaction_id,
                &material.final_checkpoint_transactions,
            )
            .await?;
        if submission.ark_transaction_id != encode_hex(&validated.output_vtxo.transaction_id()) {
            return Err(ArkFundedError::Invalid(
                "arkd submission differs from the contract-bound output VTXO",
            ));
        }
        let observed = self.client.vtxo(&validated.output_vtxo).await?;
        verify_observed_vtxo(&observed, material)?;
        let receipt = self.receipt(material, &validated.output_vtxo);
        complete_transfer(store, authorization, request_sha256, &receipt, now).await?;
        Ok(receipt)
    }

    pub async fn execute_command(
        &self,
        store: &mut ProviderStore,
        command: &ArkTransferCommand,
        now: u64,
    ) -> Result<ArkTransferReceipt, ArkFundedError> {
        if command.schema != ARK_TRANSFER_COMMAND_SCHEMA
            || !matches!(command.leg_id.as_str(), "source" | "destination")
        {
            return Err(ArkFundedError::Invalid(
                "Ark transfer command schema or leg",
            ));
        }
        let snapshot = canonical_json(&command.client_snapshot)
            .map_err(|_| ArkFundedError::Invalid("Ark client snapshot is not canonical"))?;
        let engine = ArkClientEngine::restore(&snapshot)
            .map_err(|_| ArkFundedError::Invalid("Ark client snapshot is not authorized"))?;
        let authorization = engine.authorize_transfer().map_err(|_| {
            ArkFundedError::Invalid("Ark client snapshot cannot authorize transfer")
        })?;
        let expected_effect =
            effect_id(&authorization.order_id, "ark_transfer", &command.leg_id)
                .map_err(|_| ArkFundedError::Invalid("Ark transfer effect identity"))?;
        if authorization.effect_id != expected_effect {
            return Err(ArkFundedError::Invalid(
                "Ark client snapshot uses another transfer effect",
            ));
        }
        self.execute_transfer(
            store,
            &command.session_id,
            &authorization,
            &command.material,
            now,
        )
        .await
    }

    fn validate_transfer(
        &self,
        session_id: &str,
        authorization: &ArkFundingAuthorization,
        material: &ArkTransferMaterial,
    ) -> Result<ValidatedTransfer, ArkFundedError> {
        require_hash(session_id, "session ID")?;
        require_hash(&authorization.order_id, "Order ID")?;
        require_hash(&authorization.effect_id, "effect ID")?;
        require_hash(&authorization.operator_identity_sha256, "operator identity")?;
        require_hash(&authorization.exit_package_sha256, "exit package digest")?;
        if authorization.action != "ark_transfer"
            || authorization.operator_identity_sha256 != self.client.operator_identity_sha256()
            || authorization.vtxo_id != material.output_vtxo_id
            || authorization.exit_package_sha256 != material.exit_package_sha256
        {
            return Err(ArkFundedError::Invalid(
                "funding authorization differs from the exact Ark transfer",
            ));
        }
        let asset = ArkAssetId::parse(&material.asset_id)
            .map_err(|_| ArkFundedError::Invalid("Ark asset identifier"))?;
        if asset.operator_identity_sha256() != self.client.operator_identity_sha256()
            || asset.protocol_family().as_str() != "arkade"
        {
            return Err(ArkFundedError::Invalid(
                "Ark asset differs from the configured operator",
            ));
        }
        require_hash(
            &material.signed_vtxo_graph_sha256,
            "signed VTXO graph digest",
        )?;
        require_hash(&material.exit_package_sha256, "exit package digest")?;
        require_hash(
            &material.final_ark_transaction_sha256,
            "final Ark transaction digest",
        )?;
        if material.amount_sat == 0
            || material.input_vtxo_ids.is_empty()
            || material.input_vtxo_ids.len() > 32
            || material.checkpoint_transactions.len() > MAX_CHECKPOINT_TRANSACTIONS
            || material.final_checkpoint_transactions.len() > MAX_CHECKPOINT_TRANSACTIONS
        {
            return Err(ArkFundedError::Invalid(
                "Ark transfer object count or amount is outside its bound",
            ));
        }
        let mut input_vtxos = Vec::with_capacity(material.input_vtxo_ids.len());
        for value in &material.input_vtxo_ids {
            input_vtxos.push(
                ArkOutpoint::parse(value)
                    .map_err(|_| ArkFundedError::Invalid("input VTXO identifier"))?,
            );
        }
        if input_vtxos
            .windows(2)
            .any(|pair| pair.first() >= pair.get(1))
        {
            return Err(ArkFundedError::Invalid(
                "input VTXO identifiers are not unique and sorted",
            ));
        }
        let output_vtxo = ArkOutpoint::parse(&material.output_vtxo_id)
            .map_err(|_| ArkFundedError::Invalid("output VTXO identifier"))?;
        let transaction_bytes =
            decode_lower_hex(&material.signed_ark_transaction, "signed Ark transaction")?;
        let transaction = Transaction::parse(&transaction_bytes)
            .map_err(|_| ArkFundedError::Invalid("signed Ark transaction encoding"))?;
        reject_ark_transaction_secrets(&transaction)
            .map_err(|_| ArkFundedError::Invalid("signed Ark transaction contains a secret"))?;
        let transaction_id = transaction
            .txid()
            .map_err(|_| ArkFundedError::Invalid("signed Ark transaction ID"))?;
        if transaction_id != output_vtxo.transaction_id() {
            return Err(ArkFundedError::Invalid(
                "signed Ark transaction differs from the output VTXO",
            ));
        }
        let output_index = usize::try_from(output_vtxo.output_index())
            .map_err(|_| ArkFundedError::Invalid("output VTXO index"))?;
        let output = transaction
            .outputs
            .get(output_index)
            .ok_or(ArkFundedError::Invalid(
                "output VTXO is absent from the signed Ark transaction",
            ))?;
        let output_script =
            decode_lower_hex(&material.output_script_pubkey, "output VTXO scriptPubKey")?;
        if output.value_sat != material.amount_sat || output.script_pubkey != output_script {
            return Err(ArkFundedError::Invalid(
                "signed Ark transaction output differs from the contract-bound VTXO",
            ));
        }
        let checkpoint_transaction_sha256 =
            transaction_digests(&material.checkpoint_transactions, "checkpoint transaction")?;
        let final_checkpoint_transaction_sha256 = transaction_digests(
            &material.final_checkpoint_transactions,
            "final checkpoint transaction",
        )?;
        Ok(ValidatedTransfer {
            output_vtxo,
            signed_ark_transaction_sha256: encode_hex(&sha256(&transaction_bytes)),
            checkpoint_transaction_sha256,
            final_checkpoint_transaction_sha256,
        })
    }

    fn receipt(
        &self,
        material: &ArkTransferMaterial,
        output_vtxo: &ArkOutpoint,
    ) -> ArkTransferReceipt {
        ArkTransferReceipt {
            operator_identity_sha256: self.client.operator_identity_sha256().to_owned(),
            input_vtxo_ids: material.input_vtxo_ids.clone(),
            output_vtxo_id: material.output_vtxo_id.clone(),
            signed_vtxo_graph_sha256: material.signed_vtxo_graph_sha256.clone(),
            exit_package_sha256: material.exit_package_sha256.clone(),
            ark_transaction_id: encode_hex(&output_vtxo.transaction_id()),
        }
    }
}

struct ValidatedTransfer {
    output_vtxo: ArkOutpoint,
    signed_ark_transaction_sha256: String,
    checkpoint_transaction_sha256: Vec<String>,
    final_checkpoint_transaction_sha256: Vec<String>,
}

fn verify_observed_vtxo(
    observed: &ArkdVtxo,
    material: &ArkTransferMaterial,
) -> Result<(), ArkFundedError> {
    if observed.outpoint.canonical() != material.output_vtxo_id
        || observed.amount != material.amount_sat
        || observed.script_pubkey != material.output_script_pubkey
        || observed.ark_transaction_id != encode_hex(&observed.outpoint.transaction_id())
        || !observed.is_available()
    {
        return Err(ArkFundedError::Invalid(
            "arkd observation differs from the contract-bound VTXO",
        ));
    }
    Ok(())
}

async fn complete_transfer(
    store: &mut ProviderStore,
    authorization: &ArkFundingAuthorization,
    request_sha256: String,
    receipt: &ArkTransferReceipt,
    now: u64,
) -> Result<(), ArkFundedError> {
    let public_result = serde_json::to_value(receipt)
        .map_err(|_| ArkFundedError::Invalid("Ark transfer result serialization"))?;
    let result_sha256 = canonical_value_digest(&public_result)?;
    store
        .complete_effect(&PublicEffectResult {
            effect_id: authorization.effect_id.clone(),
            request_sha256,
            result_sha256,
            public_result,
            external_reference: receipt.output_vtxo_id.clone(),
            completed_at: now,
        })
        .await?;
    Ok(())
}

fn applied_receipt(existing: StoredPublicEffect) -> Result<ArkTransferReceipt, ArkFundedError> {
    let result = existing.public_result.ok_or(ArkFundedError::Invalid(
        "applied Ark transfer has no public result",
    ))?;
    let receipt: ArkTransferReceipt = serde_json::from_value(result)
        .map_err(|_| ArkFundedError::Invalid("applied Ark transfer result shape"))?;
    if existing.external_reference.as_deref() != Some(receipt.output_vtxo_id.as_str()) {
        return Err(ArkFundedError::Invalid(
            "applied Ark transfer has another external reference",
        ));
    }
    Ok(receipt)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ArkFundedError> {
    canonical_json(value)
        .map(|bytes| encode_hex(&sha256(&bytes)))
        .map_err(|_| ArkFundedError::Invalid("Ark transfer request is not canonical"))
}

fn canonical_value_digest(value: &Value) -> Result<String, ArkFundedError> {
    canonical_json(value)
        .map(|bytes| encode_hex(&sha256(&bytes)))
        .map_err(|_| ArkFundedError::Invalid("Ark transfer result is not canonical"))
}

fn transaction_digests(
    transactions: &[String],
    subject: &'static str,
) -> Result<Vec<String>, ArkFundedError> {
    let mut unique = BTreeSet::new();
    let mut digests = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        let bytes = decode_lower_hex(transaction, subject)?;
        Transaction::parse(&bytes)
            .map_err(|_| ArkFundedError::Invalid("checkpoint transaction encoding"))?;
        let digest = encode_hex(&sha256(&bytes));
        if !unique.insert(digest.clone()) {
            return Err(ArkFundedError::Invalid(
                "checkpoint transaction set contains duplicate bytes",
            ));
        }
        digests.push(digest);
    }
    Ok(digests)
}

fn decode_lower_hex(value: &str, subject: &'static str) -> Result<Vec<u8>, ArkFundedError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() / 2 > MAX_TRANSACTION_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ArkFundedError::Invalid(subject));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(ArkFundedError::Invalid(subject))?;
            let low = hex_nibble(pair[1]).ok_or(ArkFundedError::Invalid(subject))?;
            Ok(high << 4 | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn require_hash(value: &str, subject: &'static str) -> Result<(), ArkFundedError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ArkFundedError::Invalid(subject))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::arkd::{ArkdEndpoint, ArkdExpectedOperator, ArkdLimits};

    const SIGNED_ARK_TRANSACTION: &str = "02000000000101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff02a086010000000000225120a59934408e9c1e7d1e06932683d749ea4c613143b6b5dc5c922082c31adf912610270000000000002251204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601403edc2f0dbed09ee01c4fba67320fddb0e43371e5ba8b86670d974f32370fc78eac1c3974206afae6a112bcc546a8d910305a75e5865a4b8353b1495c41cc186d00000000";

    fn rail() -> ArkFundedRail {
        let operator_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/provider/arkd-operator-regtest-v1.json")
            .canonicalize()
            .expect("operator fixture");
        let expected =
            ArkdExpectedOperator::load_document(&operator_path).expect("operator fixture");
        let client = ArkdClient::new(
            ArkdEndpoint::plaintext_regtest("127.0.0.1", 17070).expect("endpoint"),
            expected,
            ArkdLimits::default(),
        )
        .expect("arkd client");
        ArkFundedRail::new(client)
    }

    fn material(rail: &ArkFundedRail) -> (ArkFundingAuthorization, ArkTransferMaterial) {
        let raw = decode_lower_hex(SIGNED_ARK_TRANSACTION, "fixture transaction")
            .expect("fixture transaction");
        let exit_package_sha256 = "77".repeat(32);
        let authorization = ArkFundingAuthorization {
            action: "ark_transfer",
            order_id: "11".repeat(32),
            effect_id: "22".repeat(32),
            vtxo_id: "395559425d103f3c76d13a85f3443d56c853fd5ac6c5291a1a4178c4d7289196:0"
                .to_owned(),
            operator_identity_sha256: rail.client.operator_identity_sha256().to_owned(),
            exit_package_sha256: exit_package_sha256.clone(),
            exit_package_artifact_ref: "ark-exit:fixture".to_owned(),
        };
        let material = ArkTransferMaterial {
            asset_id: rail.asset_id(),
            input_vtxo_ids: vec![format!("{}:0", "aa".repeat(32))],
            output_vtxo_id: authorization.vtxo_id.clone(),
            amount_sat: 100_000,
            output_script_pubkey:
                "5120a59934408e9c1e7d1e06932683d749ea4c613143b6b5dc5c922082c31adf9126".to_owned(),
            signed_vtxo_graph_sha256: "66".repeat(32),
            exit_package_sha256,
            signed_ark_transaction: SIGNED_ARK_TRANSACTION.to_owned(),
            final_ark_transaction_sha256: encode_hex(&sha256(&raw)),
            checkpoint_transactions: Vec::new(),
            final_checkpoint_transactions: Vec::new(),
        };
        (authorization, material)
    }

    #[test]
    fn checkpoint_digests_reject_duplicates_and_malformed_transactions() {
        assert!(transaction_digests(&[], "checkpoint").is_ok());
        assert!(transaction_digests(&["00".to_owned()], "checkpoint").is_err());
        let transaction = "02000000000101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff02a086010000000000225120a59934408e9c1e7d1e06932683d749ea4c613143b6b5dc5c922082c31adf912610270000000000002251204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601403edc2f0dbed09ee01c4fba67320fddb0e43371e5ba8b86670d974f32370fc78eac1c3974206afae6a112bcc546a8d910305a75e5865a4b8353b1495c41cc186d00000000".to_owned();
        assert!(transaction_digests(core::slice::from_ref(&transaction), "checkpoint").is_ok());
        assert!(transaction_digests(&[transaction.clone(), transaction], "checkpoint").is_err());
    }

    #[test]
    fn transfer_validation_binds_authorization_operator_and_exact_output() {
        let rail = rail();
        let (authorization, material) = material(&rail);
        let validated = rail
            .validate_transfer(&"33".repeat(32), &authorization, &material)
            .expect("contract-bound transfer");
        assert_eq!(validated.output_vtxo.canonical(), authorization.vtxo_id);

        let mut changed = material.clone();
        changed.amount_sat += 1;
        assert!(
            rail.validate_transfer(&"33".repeat(32), &authorization, &changed)
                .is_err()
        );
        let mut changed = material;
        changed.exit_package_sha256 = "88".repeat(32);
        assert!(
            rail.validate_transfer(&"33".repeat(32), &authorization, &changed)
                .is_err()
        );
    }
}
