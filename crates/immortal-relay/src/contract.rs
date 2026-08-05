use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        EventClass, MKT_CANCEL_ACTIONS, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_DESCRIPTOR_STATUSES,
        MKT_ENVELOPE_SCHEMA, MKT_EXECUTABLE_PROFILES, MKT_IDENTIFIER_MAX_BYTES,
        MKT_IDENTIFIER_PATTERN, MKT_MAX_COUNTERPARTIES, MKT_MAX_DISCOVERY_CONTENT_BYTES,
        MKT_MAX_HINTS, MKT_MAX_PRIVATE_EVENT_BYTES, MKT_MAX_PROFILES,
        MKT_MAX_RECEIPT_CONTENT_BYTES, MKT_MAX_REFERENCES, MKT_MAX_TAGS,
        MKT_MINT_CREDENTIAL_BURDENS, MKT_MINT_CUSTODY_CLASSES, MKT_MINT_EVIDENCE_PROVENANCE,
        MKT_MINT_GATEWAY_POLICIES, MKT_MINT_OPERATIONS_CASHU, MKT_MINT_OPERATIONS_FEDIMINT,
        MKT_MINT_PROFILE_ID, MKT_MINT_PROFILE_VERSION, MKT_MINT_RAILS,
        MKT_MINT_ROUTE_CONTRACT_KIND, MKT_MINT_STATUS_EXTENSIONS, MKT_OFFERING_KIND,
        MKT_OFFERING_STATUSES, MKT_ORDER_KIND, MKT_OUTCOMES, MKT_PFI_PROFILE_ID,
        MKT_PFI_PROFILE_VERSION, MKT_PFI_QUALIFICATION_POLICY_KIND, MKT_PROFILE_DESCRIPTOR_KIND,
        MKT_PROVIDER_PROFILE_KIND, MKT_PROVIDER_STATUSES, MKT_PUBLIC_RECEIPT_KIND,
        MKT_PUBLIC_RECEIPT_OUTCOMES, MKT_QUOTE_CLASSES, MKT_QUOTE_KIND, MKT_RELAY_PROFILES,
        MKT_RESERVATION_CLASSES, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_STATUS_STATES,
        MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND,
    },
    gateway::{
        GatewayLimits, MKT_GIFT_WRAP_RECIPIENT_RATE_EXCEEDED, MKT_PRIVATE_REQUIRES_GIFT_WRAP,
    },
    mkt_swp_coordination::{
        MKT_SWP_COORDINATION_CONFORMANCE_ENV, MKT_SWP_COORDINATION_EXTENSION,
        MKT_SWP_COORDINATION_SWEEP_ENV, MKT_SWP_MAX_ACTIVE_RESERVATIONS_PER_BUCKET,
        MKT_SWP_MAX_FORKS_PER_SEQUENCE, MKT_SWP_MAX_PUBLIC_EVIDENCE_PER_RECORD,
        MKT_SWP_MAX_PUBLIC_TRANSACTION_BYTES, MKT_SWP_MAX_STATUS_SEQUENCE,
        MKT_SWP_STATUS_QUERY_ROW_LIMIT, coordination_conformance_sha256,
    },
    store::MKT_IDEMPOTENCY_CONFLICT_REASON,
};

pub const CONTRACT_SCHEMA: &str = "openagents.immortal.contract.v1";
pub const CONTRACT_VERSION: u32 = 1;
pub const FIXTURE_MANIFEST_PATH: &str = "contract/immortal-fixtures.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImmortalContract {
    pub identity: ContractIdentity,
    pub supported_protocols: Vec<ProtocolDescriptor>,
    pub kinds: Vec<KindDescriptor>,
    pub limits: ContractLimits,
    pub mkt: MktGrammar,
    pub reasons: ReasonContract,
    pub fixture_manifest: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContractIdentity {
    pub schema: &'static str,
    pub contract_version: u32,
    pub crate_name: &'static str,
    pub crate_version: &'static str,
    pub nips: Vec<NipSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NipSource {
    pub lane: String,
    pub repo: String,
    pub subdir: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolDescriptor {
    pub lane: &'static str,
    pub identifier: &'static str,
    pub advertisement: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindDescriptor {
    pub kind: u16,
    pub lane: &'static str,
    pub identifier: &'static str,
    pub name: &'static str,
    pub classification: &'static str,
    pub publication: &'static str,
    pub immutability: &'static str,
    pub enforcement_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContractLimits {
    pub gateway: Vec<LimitDescriptor>,
    pub mkt: MktLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimitDescriptor {
    pub name: &'static str,
    pub environment: &'static str,
    pub default: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub unit: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktLimits {
    pub discovery_content_bytes: usize,
    pub receipt_content_bytes: usize,
    pub private_signed_record_bytes: usize,
    pub tags: usize,
    pub counterparties: usize,
    pub causal_or_evidence_references: usize,
    pub profiles: usize,
    pub relay_or_endpoint_hints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktGrammar {
    pub schema: &'static str,
    pub executable_profiles: Vec<ExecutableProfile>,
    pub relay_profiles: Vec<RelayProfile>,
    pub mkt_swp: MktSwpGrammar,
    pub mkt_pfi: MktPfiGrammar,
    pub mkt_mint: MktMintGrammar,
    pub required_tags: BTreeMap<&'static str, Vec<&'static str>>,
    pub enums: BTreeMap<&'static str, Vec<&'static str>>,
    pub identifiers: BTreeMap<&'static str, IdentifierGrammar>,
    pub content_envelope: Vec<&'static str>,
    pub opaque_transport: OpaqueTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutableProfile {
    pub id: &'static str,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayProfile {
    pub id: &'static str,
    pub version: u64,
    pub scope: &'static str,
    pub advertisement: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktSwpGrammar {
    pub id: &'static str,
    pub version: u64,
    pub swap_contract_kind: u16,
    pub swap_contract_publication: &'static str,
    pub contract_digest_validation: &'static str,
    pub network_id_pattern: &'static str,
    pub asset_id_pattern: &'static str,
    pub canonical_amount_pattern: &'static str,
    pub offering_required_members: Vec<&'static str>,
    pub public_offering_forbidden_members: Vec<&'static str>,
    pub public_receipt_forbidden_members: Vec<&'static str>,
    pub evidence_classes: Vec<&'static str>,
    pub evidence_rungs: Vec<&'static str>,
    pub evidence_reference_validation: &'static str,
    pub public_receipt_outcomes: Vec<&'static str>,
    pub forbidden_custody_members: Vec<&'static str>,
    pub upstream_fixture_cases: usize,
    pub coordination: MktSwpCoordinationGrammar,
    pub client_engine: MktSwpClientContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktSwpCoordinationGrammar {
    pub extension: &'static str,
    pub enabled_by_default: bool,
    pub activation_environment: &'static str,
    pub conformance_sha256: String,
    pub sweep_environment: &'static str,
    pub required_configuration: Vec<&'static str>,
    pub private_capacity_extension_member: &'static str,
    pub reservation_accounting: &'static str,
    pub allocation_commitment: &'static str,
    pub covenant_reserve_identity: &'static str,
    pub reservation_proof_strength: BTreeMap<&'static str, u16>,
    pub active_reservations_per_bucket: usize,
    pub deadline: &'static str,
    pub timeout_mutation: &'static str,
    pub timeout_forbidden_effects: Vec<&'static str>,
    pub status_projection: &'static str,
    pub status_sequence_maximum: u64,
    pub forks_per_sequence: usize,
    pub status_query_rows: usize,
    pub public_evidence_hook: &'static str,
    pub public_evidence_per_record: usize,
    pub public_transaction_bytes: usize,
    pub observation_kind: u16,
    pub observation_namespace: &'static str,
    pub observation_authority: &'static str,
    pub durable_private_state: &'static str,
    pub multi_process_consistency: &'static str,
    pub on_relay_output_orderbook: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktSwpClientContract {
    pub status: &'static str,
    pub build_targets: Vec<&'static str>,
    pub requester_flows: Vec<&'static str>,
    pub constructed_record_kinds: Vec<u16>,
    pub funding_requires: Vec<&'static str>,
    pub wallet_boundary: &'static str,
    pub persistence: &'static str,
    pub recovery: Vec<&'static str>,
    pub fixture: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktPfiGrammar {
    pub id: &'static str,
    pub version: u64,
    pub qualification_policy_kind: u16,
    pub scope: &'static str,
    pub fiat_asset_id_pattern: &'static str,
    pub crypto_asset_id_pattern: &'static str,
    pub market_id_preimage: &'static str,
    pub canonical_amount_pattern: &'static str,
    pub offering_required_members: Vec<&'static str>,
    pub risk_classes: Vec<&'static str>,
    pub evidence_classes: Vec<&'static str>,
    pub evidence_rungs: Vec<&'static str>,
    pub credential_transport: &'static str,
    pub public_receipt: &'static str,
    pub external_authority: &'static str,
    pub upstream_fixture_cases: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MktMintGrammar {
    pub id: &'static str,
    pub version: u64,
    pub route_contract_kind: u16,
    pub scope: &'static str,
    pub discovery_authority: &'static str,
    pub nip87_announcement_kinds: BTreeMap<&'static str, &'static str>,
    pub nip87_recommendation_kind_rejected: &'static str,
    pub rails: Vec<&'static str>,
    pub custody_classes: BTreeMap<&'static str, &'static str>,
    pub custody_disclosure: &'static str,
    pub operations: BTreeMap<&'static str, Vec<&'static str>>,
    pub sides_law: &'static str,
    pub canonical_amount_pattern: &'static str,
    pub offering_required_members: Vec<&'static str>,
    pub credential_burdens: Vec<&'static str>,
    pub gateway_policies: Vec<&'static str>,
    pub route_contract_publication: &'static str,
    pub route_contract_alt: &'static str,
    pub contract_digest_validation: &'static str,
    pub contract_members: Vec<&'static str>,
    pub status_extensions: Vec<&'static str>,
    pub evidence_provenance: Vec<&'static str>,
    pub evidence_reference_validation: &'static str,
    pub forbidden_custody_members: Vec<&'static str>,
    pub external_authority: &'static str,
    pub upstream_fixture_cases: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentifierGrammar {
    pub pattern: &'static str,
    pub maximum_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpaqueTransport {
    pub outer_kind: u16,
    pub bare_private_publication: &'static str,
    pub relay_validates_inner: bool,
    pub read_authorization: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonContract {
    pub ok: Vec<ReasonDescriptor>,
    pub closed: Vec<ReasonDescriptor>,
    pub prefixes: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonDescriptor {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    sources: Vec<SourceManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestEntry {
    name: String,
    repo: String,
    subdir: String,
    branch: String,
    commit: String,
    tree_url: String,
    synced_at: String,
    files: usize,
}

pub fn contract() -> Result<ImmortalContract, String> {
    Ok(ImmortalContract {
        identity: ContractIdentity {
            schema: CONTRACT_SCHEMA,
            contract_version: CONTRACT_VERSION,
            crate_name: env!("CARGO_CRATE_NAME"),
            crate_version: env!("CARGO_PKG_VERSION"),
            nips: nip_sources()?,
        },
        supported_protocols: supported_protocols(),
        kinds: mkt_kinds(),
        limits: limits(),
        mkt: mkt_grammar(),
        reasons: reasons(),
        fixture_manifest: FIXTURE_MANIFEST_PATH,
    })
}

pub fn contract_json() -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(&contract()?)
        .map_err(|error| format!("could not serialize contract: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn nip_sources() -> Result<Vec<NipSource>, String> {
    let manifest =
        serde_json::from_str::<SourceManifest>(include_str!("../../../nips/manifest.json"))
            .map_err(|error| format!("invalid embedded NIP manifest: {error}"))?;
    let expected = ["official", "block", "openagents"];
    if manifest.sources.len() != expected.len() {
        return Err("embedded NIP manifest must contain exactly three source lanes".to_owned());
    }
    manifest
        .sources
        .into_iter()
        .zip(expected)
        .map(|(source, expected_name)| {
            if source.name != expected_name {
                return Err(format!(
                    "embedded NIP source lane {:?} must be {expected_name:?}",
                    source.name
                ));
            }
            if source.commit.len() != 40
                || !source
                    .commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!(
                    "embedded NIP source {} has an invalid commit",
                    source.name
                ));
            }
            let _non_identity_metadata = (
                source.branch,
                source.tree_url,
                source.synced_at,
                source.files,
            );
            Ok(NipSource {
                lane: source.name,
                repo: source.repo,
                subdir: source.subdir,
                commit: source.commit,
            })
        })
        .collect()
}

fn supported_protocols() -> Vec<ProtocolDescriptor> {
    vec![
        protocol("official", "NIP-01", "always", "implemented"),
        protocol("official", "NIP-09", "always", "implemented"),
        protocol("official", "NIP-11", "always", "implemented"),
        protocol("official", "NIP-17", "relay_url", "implemented"),
        protocol("official", "NIP-29", "relay_signer", "implemented"),
        protocol(
            "official",
            "NIP-32",
            "mkt_swp_coordination_exact_conformance",
            "implemented_for_handler_observations",
        ),
        protocol("official", "NIP-40", "always", "implemented"),
        protocol("official", "NIP-42", "relay_url", "implemented"),
        protocol("official", "NIP-45", "always", "implemented"),
        protocol("official", "NIP-50", "always", "implemented"),
        protocol("official", "NIP-65", "always", "implemented"),
        protocol("official", "NIP-70", "relay_url", "implemented"),
        protocol("official", "NIP-86", "management_pubkey", "implemented"),
        protocol("official", "NIP-94", "always", "implemented"),
        protocol(
            "official",
            "NIP-98",
            "management_pubkey_or_media",
            "implemented",
        ),
        protocol("block", "nip-mp", "always", "implemented"),
        protocol("block", "nip-oa", "always", "implemented"),
        protocol("block", "nip-rs", "always", "implemented"),
        protocol("block", "nip-aa", "relay_url", "implemented"),
        protocol("block", "nip-ae", "relay_url", "implemented"),
        protocol("block", "nip-am", "relay_url", "implemented"),
        protocol("block", "nip-ao", "relay_url", "implemented"),
        protocol("block", "nip-ap", "relay_url", "implemented"),
        protocol("block", "nip-er", "relay_url", "implemented"),
        protocol(
            "block",
            "nip-dv",
            "relay_url_and_relay_signer",
            "implemented",
        ),
        protocol(
            "block",
            "nip-ia",
            "relay_url_and_relay_signer",
            "implemented",
        ),
        protocol(
            "block",
            "nip-wp",
            "relay_url_and_management_pubkey",
            "implemented",
        ),
        protocol("block", "nip-cw", "never", "safe_degradation_only"),
        protocol("block", "nip-gs", "never", "no_relay_handler"),
        protocol("block", "nip-pl", "never", "executor_unconfigured"),
        protocol("openagents", "NIP-OT/PG", "never", "client_only"),
        protocol("openagents", "nip-mkt", "relay_url", "implemented_base"),
        protocol("openagents", "mkt-swp:1", "relay_url", "relay_observable"),
        protocol(
            "openagents",
            "nip-mkt-pfi:1",
            "relay_url_and_local_conformance",
            "relay_observable",
        ),
        protocol(
            "openagents",
            "nip-mkt-mint:1",
            "relay_url_and_local_conformance",
            "relay_observable",
        ),
        protocol(
            "openagents",
            MKT_SWP_COORDINATION_EXTENSION,
            "exact_conformance_digest_and_relay_signer",
            "optional_noncustodial_handler",
        ),
    ]
}

const fn protocol(
    lane: &'static str,
    identifier: &'static str,
    advertisement: &'static str,
    status: &'static str,
) -> ProtocolDescriptor {
    ProtocolDescriptor {
        lane,
        identifier,
        advertisement,
        status,
    }
}

fn mkt_kinds() -> Vec<KindDescriptor> {
    [
        (
            MKT_PROVIDER_PROFILE_KIND,
            "provider_profile",
            "public_head",
            "nip01_addressable",
            "relay",
        ),
        (
            MKT_OFFERING_KIND,
            "offering",
            "public_head",
            "nip01_addressable",
            "relay",
        ),
        (
            MKT_PROFILE_DESCRIPTOR_KIND,
            "profile_descriptor",
            "public_head",
            "nip01_addressable",
            "relay",
        ),
        (
            MKT_PUBLIC_RECEIPT_KIND,
            "public_market_receipt",
            "public_head",
            "nip01_addressable",
            "relay",
        ),
        (
            MKT_RFQ_KIND,
            "rfq",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_QUOTE_KIND,
            "quote",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_ORDER_KIND,
            "order",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_STATUS_KIND,
            "status",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_CANCEL_KIND,
            "cancel",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_CLOSE_KIND,
            "close",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_SWP_SWAP_CONTRACT_KIND,
            "mkt_swp_swap_contract",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
        (
            MKT_PFI_QUALIFICATION_POLICY_KIND,
            "mkt_pfi_qualification_policy",
            "public_head",
            "nip01_addressable",
            "relay",
        ),
        (
            MKT_MINT_ROUTE_CONTRACT_KIND,
            "mkt_mint_route_contract",
            "private_wrapped",
            "exact_signed_coordinate",
            "client_and_internal_store",
        ),
    ]
    .into_iter()
    .map(
        |(kind, name, publication, immutability, enforcement_scope)| KindDescriptor {
            kind,
            lane: "openagents",
            identifier: "NIP-MKT",
            name,
            classification: match EventClass::from_kind(kind) {
                EventClass::Addressable => "addressable",
                EventClass::Replaceable => "replaceable",
                EventClass::Ephemeral => "ephemeral",
                EventClass::Regular => "regular",
            },
            publication,
            immutability,
            enforcement_scope,
        },
    )
    .collect()
}

fn limits() -> ContractLimits {
    let defaults = GatewayLimits::default();
    ContractLimits {
        gateway: vec![
            limit(
                "frame_bytes",
                "IMMORTAL_MAX_FRAME_BYTES",
                defaults.max_frame_bytes as u64,
                1024,
                16_777_216,
                "bytes",
            ),
            limit(
                "subscriptions_per_connection",
                "IMMORTAL_MAX_SUBSCRIPTIONS",
                defaults.max_subscriptions as u64,
                1,
                1024,
                "count",
            ),
            limit(
                "filters_per_request",
                "IMMORTAL_MAX_FILTERS",
                defaults.max_filters as u64,
                1,
                256,
                "count",
            ),
            limit(
                "results_per_filter",
                "IMMORTAL_MAX_LIMIT",
                defaults.max_limit as u64,
                1,
                100_000,
                "count",
            ),
            limit(
                "query_cost",
                "IMMORTAL_MAX_QUERY_COST",
                defaults.max_query_cost as u64,
                1,
                1_000_000_000,
                "estimated_rows",
            ),
            limit(
                "events_per_minute_ip",
                "IMMORTAL_RATE_EVENTS_PER_MIN_IP",
                defaults.events_per_minute_ip as u64,
                1,
                u32::MAX as u64,
                "events_per_minute",
            ),
            limit(
                "events_per_minute_pubkey",
                "IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY",
                defaults.events_per_minute_pubkey as u64,
                1,
                u32::MAX as u64,
                "events_per_minute",
            ),
            limit(
                "gift_wraps_per_minute_recipient",
                "IMMORTAL_RATE_GIFT_WRAPS_PER_MIN_RECIPIENT",
                defaults.gift_wraps_per_minute_recipient as u64,
                1,
                u32::MAX as u64,
                "events_per_minute",
            ),
            limit(
                "observer_events_per_second_ip",
                "IMMORTAL_RATE_OBSERVER_PER_SEC_IP",
                defaults.observer_events_per_second_ip as u64,
                1,
                u32::MAX as u64,
                "events_per_second",
            ),
            limit(
                "observer_events_per_second_agent",
                "IMMORTAL_RATE_OBSERVER_PER_SEC_AGENT",
                defaults.observer_events_per_second_agent as u64,
                1,
                u32::MAX as u64,
                "events_per_second",
            ),
            limit(
                "requests_per_minute_ip",
                "IMMORTAL_RATE_REQ_PER_MIN_IP",
                defaults.req_per_minute_ip as u64,
                1,
                u32::MAX as u64,
                "requests_per_minute",
            ),
            limit(
                "media_requests_per_minute_ip",
                "IMMORTAL_RATE_MEDIA_PER_MIN_IP",
                defaults.media_per_minute_ip as u64,
                1,
                u32::MAX as u64,
                "requests_per_minute",
            ),
            limit(
                "media_requests_per_minute_pubkey",
                "IMMORTAL_RATE_MEDIA_PER_MIN_PUBKEY",
                defaults.media_per_minute_pubkey as u64,
                1,
                u32::MAX as u64,
                "requests_per_minute",
            ),
            limit(
                "connections_per_ip",
                "IMMORTAL_MAX_CONNECTIONS_PER_IP",
                defaults.max_connections_per_ip as u64,
                1,
                4096,
                "count",
            ),
            limit(
                "send_queue_capacity",
                "IMMORTAL_SEND_QUEUE_CAPACITY",
                defaults.send_queue_capacity as u64,
                8,
                65_536,
                "messages",
            ),
        ],
        mkt: MktLimits {
            discovery_content_bytes: MKT_MAX_DISCOVERY_CONTENT_BYTES,
            receipt_content_bytes: MKT_MAX_RECEIPT_CONTENT_BYTES,
            private_signed_record_bytes: MKT_MAX_PRIVATE_EVENT_BYTES,
            tags: MKT_MAX_TAGS,
            counterparties: MKT_MAX_COUNTERPARTIES,
            causal_or_evidence_references: MKT_MAX_REFERENCES,
            profiles: MKT_MAX_PROFILES,
            relay_or_endpoint_hints: MKT_MAX_HINTS,
        },
    }
}

const fn limit(
    name: &'static str,
    environment: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
    unit: &'static str,
) -> LimitDescriptor {
    LimitDescriptor {
        name,
        environment,
        default,
        minimum,
        maximum,
        unit,
    }
}

fn mkt_grammar() -> MktGrammar {
    let mut required_tags = BTreeMap::new();
    required_tags.insert(
        "private_common",
        vec!["d", "session", "profile", "p", "alt"],
    );
    required_tags.insert(
        "provider_profile",
        vec!["d", "status", "published_at", "profile"],
    );
    required_tags.insert(
        "offering",
        vec!["d", "status", "published_at", "profile", "provider"],
    );
    required_tags.insert(
        "profile_descriptor",
        vec!["d", "version", "x", "r", "status"],
    );
    required_tags.insert(
        "public_market_receipt",
        vec!["d", "profile", "outcome", "x", "role"],
    );
    required_tags.insert("rfq", vec!["provider p", "offering a", "expiration"]);
    required_tags.insert(
        "quote",
        vec!["rfq e", "requester p", "expiration", "quote", "reservation"],
    );
    required_tags.insert("order", vec!["quote e", "provider p"]);
    required_tags.insert(
        "status",
        vec!["order e", "seq", "state", "previous e when seq > 0"],
    );
    required_tags.insert("cancel", vec!["order e", "action", "reason"]);
    required_tags.insert("close", vec!["order e", "outcome", "terminal_at"]);
    required_tags.insert(
        "mkt_swp_swap_contract",
        vec![
            "d", "session", "profile", "p", "alt", "order e", "quote e", "x", "role",
        ],
    );
    required_tags.insert(
        "mkt_pfi_qualification_policy",
        vec![
            "d",
            "profile=mkt-pfi:1",
            "status",
            "version",
            "published_at",
            "x",
            "alt",
        ],
    );
    required_tags.insert(
        "mkt_pfi_offering",
        vec![
            "market",
            "qualification-policy a",
            "qualification-policy e",
            "direction",
            "risk",
            "rail",
        ],
    );
    required_tags.insert(
        "mkt_mint_route_contract",
        vec![
            "d",
            "session",
            "profile",
            "p",
            "alt",
            "quote e",
            "order e",
            "status e when accepted_status_event_id is not null",
            "rail",
            "role",
            "x",
        ],
    );

    let mut enums = BTreeMap::new();
    enums.insert("cancel_action", MKT_CANCEL_ACTIONS.to_vec());
    enums.insert("close_outcome", MKT_OUTCOMES.to_vec());
    enums.insert("descriptor_status", MKT_DESCRIPTOR_STATUSES.to_vec());
    enums.insert("offering_status", MKT_OFFERING_STATUSES.to_vec());
    enums.insert("provider_status", MKT_PROVIDER_STATUSES.to_vec());
    enums.insert(
        "public_receipt_outcome",
        MKT_PUBLIC_RECEIPT_OUTCOMES.to_vec(),
    );
    enums.insert("quote", MKT_QUOTE_CLASSES.to_vec());
    enums.insert("reservation", MKT_RESERVATION_CLASSES.to_vec());
    enums.insert("status_state", MKT_STATUS_STATES.to_vec());

    let mut identifiers = BTreeMap::new();
    identifiers.insert(
        "provider_id_offering_id_profile_id",
        IdentifierGrammar {
            pattern: MKT_IDENTIFIER_PATTERN,
            maximum_bytes: MKT_IDENTIFIER_MAX_BYTES,
        },
    );
    identifiers.insert(
        "private_d_and_session",
        IdentifierGrammar {
            pattern: "^[0-9a-f]{64}$",
            maximum_bytes: 64,
        },
    );

    MktGrammar {
        schema: MKT_ENVELOPE_SCHEMA,
        executable_profiles: MKT_EXECUTABLE_PROFILES
            .iter()
            .map(|(id, version)| ExecutableProfile {
                id,
                version: *version,
            })
            .collect(),
        relay_profiles: MKT_RELAY_PROFILES
            .iter()
            .map(|(id, version)| RelayProfile {
                id,
                version: *version,
                scope: "relay_observable_only",
                advertisement: "relay_url_and_local_conformance",
            })
            .collect(),
        mkt_swp: MktSwpGrammar {
            id: MKT_SWP_PROFILE_ID,
            version: MKT_SWP_PROFILE_VERSION,
            swap_contract_kind: MKT_SWP_SWAP_CONTRACT_KIND,
            swap_contract_publication: "private_signed_record_nip59_only",
            contract_digest_validation: "lower_hex_shape_and_x_body_equality; rfc8785_recomputation_is_client_or_handler_scope",
            network_id_pattern: "^bip122:[0-9a-f]{32}$",
            asset_id_pattern: "^swp:1:bip122:[0-9a-f]{32}:btc:(chain|lightning)$",
            canonical_amount_pattern: "^(0|[1-9][0-9]*)$",
            offering_required_members: vec![
                "swap_types",
                "sides",
                "networks",
                "script_modes",
                "reservation_proof_classes",
                "confirmation_policies",
                "availability",
                "evm_extension",
            ],
            public_offering_forbidden_members: vec![
                "live_inventory",
                "inventory",
                "utxo",
                "utxos",
                "channel_balance",
                "channel_balances",
                "invoice",
                "invoices",
                "address",
                "addresses",
                "script",
                "scripts",
                "payment_hash",
                "payment_hashes",
                "reserve_witness",
                "reserve_witnesses",
            ],
            public_receipt_forbidden_members: vec![
                "session_id",
                "counterparty",
                "counterparties",
                "amount",
                "input_amount",
                "output_amount",
                "asset_pair",
                "input_asset_id",
                "output_asset_id",
                "route",
                "payment_hash",
                "invoice",
                "transaction_id",
                "txid",
                "timing_ladder",
                "evidence",
                "evidence_refs",
            ],
            evidence_classes: vec![
                "invoice",
                "lightning_htlc",
                "lightning_payment",
                "bitcoin_transaction",
                "bitcoin_output",
                "bitcoin_spend",
                "reservation",
                "covenant_reserve",
                "claim",
                "refund",
                "reorg",
                "replacement",
            ],
            evidence_rungs: vec![
                "pledged", "reserved", "measured", "verified", "paid", "settled",
            ],
            evidence_reference_validation: "class_rail_compatibility; lower_hex_payment_or_transaction_ids; bitcoin_output_and_spend_txid_vout; reservation_reorg_replacement_refs_are_bounded_opaque",
            public_receipt_outcomes: MKT_PUBLIC_RECEIPT_OUTCOMES.to_vec(),
            forbidden_custody_members: vec![
                "seed",
                "wallet-seed",
                "mnemonic",
                "xprv",
                "private_key",
                "privateKey",
                "claim_private_key",
                "refund_private_key",
                "preimage",
                "macaroon",
                "lnd-macaroon",
                "nwc",
                "nwc_string",
                "nwc-uri",
                "bearer_token",
                "wallet_credential",
                "wallet_rpc_payload",
                "musig_secret_nonce",
                "secretNonce",
                "signing_nonce",
            ],
            upstream_fixture_cases: 70,
            coordination: MktSwpCoordinationGrammar {
                extension: MKT_SWP_COORDINATION_EXTENSION,
                enabled_by_default: false,
                activation_environment: MKT_SWP_COORDINATION_CONFORMANCE_ENV,
                conformance_sha256: coordination_conformance_sha256(),
                sweep_environment: MKT_SWP_COORDINATION_SWEEP_ENV,
                required_configuration: vec![
                    "relay_url",
                    "relay_signer",
                    "exact_conformance_digest",
                ],
                private_capacity_extension_member: "reservation_terms.handler_committed_capacity",
                reservation_accounting: "provider_signed_none_soft_hard; provider_wide_reservation_ids; bucket_wide_sequence_and_row_bound; conflicting_or_overallocated_claims_retained_inactive",
                allocation_commitment: "strictly_increasing_sequence_and_new_active_set_commitment_per_provider_bucket",
                covenant_reserve_identity: "sha256(covenant.funding_ref); globally_locked_across_buckets",
                reservation_proof_strength: BTreeMap::from([
                    ("provider_signed", 10),
                    ("handler_accounted", 20),
                    ("third_party_guarantee", 40),
                    ("lightning_liquidity", 50),
                    ("utxo_control", 60),
                    ("funded_htlc", 80),
                    ("covenant_reserve", 100),
                ]),
                active_reservations_per_bucket: MKT_SWP_MAX_ACTIVE_RESERVATIONS_PER_BUCKET,
                deadline: "minimum_of_nip40_reservation_and_profile_timeout",
                timeout_mutation: "active_reservation_to_released_only",
                timeout_forbidden_effects: vec![
                    "sign",
                    "cancel",
                    "accept",
                    "settle",
                    "refund",
                    "close",
                    "publish_participant_status",
                ],
                status_projection: "dense_per_session_order_author",
                status_sequence_maximum: MKT_SWP_MAX_STATUS_SEQUENCE,
                forks_per_sequence: MKT_SWP_MAX_FORKS_PER_SEQUENCE,
                status_query_rows: MKT_SWP_STATUS_QUERY_ROW_LIMIT,
                public_evidence_hook: "bitcoin_transaction_v1",
                public_evidence_per_record: MKT_SWP_MAX_PUBLIC_EVIDENCE_PER_RECORD,
                public_transaction_bytes: MKT_SWP_MAX_PUBLIC_TRANSACTION_BYTES,
                observation_kind: 1_985,
                observation_namespace: "openagents.mkt-swp.observation",
                observation_authority: "observation_not_authority",
                durable_private_state: "signed_identifiers_bounded_accounting_and_hashes_only",
                multi_process_consistency: "postgres_advisory_locks_and_transactions",
                on_relay_output_orderbook: false,
            },
            client_engine: MktSwpClientContract {
                status: "implemented_client_only",
                build_targets: vec!["native", "wasm32-unknown-unknown"],
                requester_flows: vec!["submarine", "reverse", "chain"],
                constructed_record_kinds: vec![
                    MKT_RFQ_KIND,
                    MKT_QUOTE_KIND,
                    MKT_ORDER_KIND,
                    MKT_STATUS_KIND,
                    MKT_CANCEL_KIND,
                    MKT_CLOSE_KIND,
                    MKT_SWP_SWAP_CONTRACT_KIND,
                ],
                funding_requires: vec![
                    "accepted_quote_and_order",
                    "matching_bilateral_swap_contract",
                    "rfc8785_contract_digest",
                    "public_rail_verification",
                    "persisted_exit_package",
                    "external_wallet_authorization_callback",
                ],
                wallet_boundary: "external_callbacks_only; no seed, spend key, unreleased preimage, macaroon, NWC string, or signing nonce",
                persistence: "signed_records, public_verifier_inputs, exit_packages, and external-effect results; authorization is rederived after restore",
                recovery: vec![
                    "per_signer_gap_and_fork_surface",
                    "timeout_ladder",
                    "claim_or_refund_assembly",
                    "coordinator_independent_direct_recovery",
                    "presigned_keyless_esplora_broadcast",
                    "explicit_unresolved_loss",
                ],
                fixture: "tests/fixtures/nipmkt/swp-client-engine-v1.json",
            },
        },
        mkt_pfi: MktPfiGrammar {
            id: MKT_PFI_PROFILE_ID,
            version: MKT_PFI_PROFILE_VERSION,
            qualification_policy_kind: MKT_PFI_QUALIFICATION_POLICY_KIND,
            scope: "relay_observable_only",
            fiat_asset_id_pattern: "^iso4217:[A-Z]{3}$",
            crypto_asset_id_pattern: "^caip19:<canonical-caip19-asset-id>$",
            market_id_preimage: "mkt-pfi-v1\\0<fiat_asset_id>\\0<crypto_asset_id>",
            canonical_amount_pattern: "^(0|[1-9][0-9]*)$",
            offering_required_members: vec![
                "market_id",
                "fiat_asset",
                "crypto_asset",
                "on_ramp",
                "off_ramp",
                "fee_bps",
                "qualification_policy_event_id",
                "qualification_policy_sha256",
                "credential_burden",
                "rail_ids",
                "risk_classes",
                "jurisdictions",
                "custody_dimensions",
            ],
            risk_classes: vec![
                "atomic",
                "escrowed",
                "reserved",
                "guaranteed",
                "best-effort",
            ],
            evidence_classes: vec![
                "rail_receipt",
                "institution_confirmation",
                "beneficiary_attestation",
                "escrow_funding",
                "escrow_release",
                "ledger_finality",
                "reversibility_window_elapsed",
                "refund_confirmation",
                "chargeback_confirmation",
                "guarantee_reserve",
                "guarantee_payout",
                "dispute_disposition",
            ],
            evidence_rungs: vec![
                "pledged", "reserved", "observed", "verified", "paid", "settled",
            ],
            credential_transport: "commitment_only; presentation_bytes_direct_encrypted_off_relay",
            public_receipt: "redacted_outcome_only_with_optional_non_bearer_public_safe_reference",
            external_authority: "credential_rail_guarantee_reserve_escrow_dispute_and_settlement_verification_not_claimed",
            upstream_fixture_cases: 41,
        },
        mkt_mint: MktMintGrammar {
            id: MKT_MINT_PROFILE_ID,
            version: MKT_MINT_PROFILE_VERSION,
            route_contract_kind: MKT_MINT_ROUTE_CONTRACT_KIND,
            scope: "relay_observable_only",
            discovery_authority: "official_nip87_announcement_cross_referenced_never_duplicated",
            nip87_announcement_kinds: BTreeMap::from([("cashu", "38172"), ("fedimint", "38173")]),
            nip87_recommendation_kind_rejected: "38000",
            rails: MKT_MINT_RAILS.to_vec(),
            custody_classes: MKT_MINT_CUSTODY_CLASSES.iter().copied().collect(),
            custody_disclosure: "custody_class_must_equal_the_rail_class; a_mint_or_federation_route_cannot_present_as_noncustodial",
            operations: BTreeMap::from([
                ("cashu", MKT_MINT_OPERATIONS_CASHU.to_vec()),
                ("fedimint", MKT_MINT_OPERATIONS_FEDIMINT.to_vec()),
            ]),
            sides_law: "decimal_string_amounts; max_0_disables_and_requires_min_0; omission_invalid; fedimint_deposit_disabled_in_version_1; enabled_requires_0_lt_min_le_max",
            canonical_amount_pattern: "^(0|[1-9][0-9]*)$",
            offering_required_members: vec![
                "nip87_ref",
                "rail",
                "market",
                "sides",
                "operations",
                "protocol_revisions",
                "custody_class",
                "credential_burden",
                "gateway_policy",
            ],
            credential_burdens: MKT_MINT_CREDENTIAL_BURDENS.to_vec(),
            gateway_policies: MKT_MINT_GATEWAY_POLICIES.to_vec(),
            route_contract_publication: "private_signed_record_nip59_only",
            route_contract_alt: "MKT-MINT route contract",
            contract_digest_validation: "lower_hex_shape_and_x_body_equality; rfc8785_recomputation_is_client_or_handler_scope",
            contract_members: vec![
                "quote_event_id",
                "order_event_id",
                "accepted_status_event_id",
                "operation",
                "native_request_sha256",
                "native_quote_id_sha256",
                "native_quote_sha256",
                "terms_sha256",
                "custody_sha256",
                "verifier_policy_sha256",
                "external_effect_ids_sha256",
                "recovery_package_sha256",
            ],
            status_extensions: MKT_MINT_STATUS_EXTENSIONS.to_vec(),
            evidence_provenance: MKT_MINT_EVIDENCE_PROVENANCE.to_vec(),
            evidence_reference_validation: "closed_receipt_digest_issuer_provenance_shape; quote_receipts_cannot_claim_paid_issued_refunded_settled; payment_receipts_cannot_claim_issued",
            forbidden_custody_members: vec![
                "proof",
                "proofs",
                "cashu_token",
                "note",
                "notes",
                "blinded_message",
                "blinding_factor",
                "secret",
                "preimage",
                "macaroon",
                "seed",
                "mnemonic",
                "private_key",
                "spend_key",
                "claim_private_key",
                "refund_private_key",
                "recovery_secret",
                "access_token",
                "bearer_token",
                "nwc",
            ],
            external_authority: "mint_federation_gateway_lightning_chain_and_price_feed_verification_not_claimed",
            upstream_fixture_cases: 29,
        },
        required_tags,
        enums,
        identifiers,
        content_envelope: vec!["schema", "profile", "profile_version", "session_id"],
        opaque_transport: OpaqueTransport {
            outer_kind: 1_059,
            bare_private_publication: "rejected",
            relay_validates_inner: false,
            read_authorization: "nip42_authenticated_exact_single_p_recipient",
        },
    }
}

fn reasons() -> ReasonContract {
    ReasonContract {
        ok: vec![
            ReasonDescriptor {
                code: "stored",
                message: "",
            },
            ReasonDescriptor {
                code: "duplicate",
                message: "duplicate: already have this event",
            },
            ReasonDescriptor {
                code: "blocked",
                message: "blocked: {bounded_detail}",
            },
            ReasonDescriptor {
                code: "relay_policy",
                message: "restricted: event is not allowed by relay policy",
            },
            ReasonDescriptor {
                code: "content_too_large",
                message: "invalid: event content is too large",
            },
            ReasonDescriptor {
                code: "too_many_tags",
                message: "invalid: event has too many tags",
            },
            ReasonDescriptor {
                code: "timestamp_outside_bounds",
                message: "invalid: event timestamp is outside relay bounds",
            },
            ReasonDescriptor {
                code: "auth_event",
                message: "invalid: authentication events cannot be published",
            },
            ReasonDescriptor {
                code: "deleted",
                message: "blocked: event is covered by a deletion request",
            },
            ReasonDescriptor {
                code: "superseded",
                message: "duplicate: newer replaceable event already stored",
            },
            ReasonDescriptor {
                code: "mkt_private_requires_gift_wrap",
                message: MKT_PRIVATE_REQUIRES_GIFT_WRAP,
            },
            ReasonDescriptor {
                code: "mkt_idempotency_conflict",
                message: MKT_IDEMPOTENCY_CONFLICT_REASON,
            },
            ReasonDescriptor {
                code: "gift_wrap_recipient_rate",
                message: MKT_GIFT_WRAP_RECIPIENT_RATE_EXCEEDED,
            },
        ],
        closed: vec![
            ReasonDescriptor {
                code: "request_rate",
                message: "rate-limited: REQ rate exceeded",
            },
            ReasonDescriptor {
                code: "count_rate",
                message: "rate-limited: COUNT rate exceeded",
            },
            ReasonDescriptor {
                code: "too_many_filters",
                message: "restricted: too many filters",
            },
            ReasonDescriptor {
                code: "gift_wrap_auth_required",
                message: "auth-required: gift-wrap reads require recipient authentication",
            },
            ReasonDescriptor {
                code: "gift_wrap_self_scope_required",
                message: "restricted: gift-wrap reads must be scoped to #p self",
            },
            ReasonDescriptor {
                code: "query_cost",
                message: "restricted: query cost exceeds the configured limit",
            },
            ReasonDescriptor {
                code: "count_bound",
                message: "restricted: count exceeds the configured query bound",
            },
        ],
        prefixes: vec![
            "auth-required:",
            "blocked:",
            "duplicate:",
            "error:",
            "invalid:",
            "rate-limited:",
            "restricted:",
        ],
    }
}
