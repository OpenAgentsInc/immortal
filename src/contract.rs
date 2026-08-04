use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        EventClass, MKT_CANCEL_ACTIONS, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_DESCRIPTOR_STATUSES,
        MKT_ENVELOPE_SCHEMA, MKT_EXECUTABLE_PROFILES, MKT_IDENTIFIER_MAX_BYTES,
        MKT_IDENTIFIER_PATTERN, MKT_MAX_COUNTERPARTIES, MKT_MAX_DISCOVERY_CONTENT_BYTES,
        MKT_MAX_HINTS, MKT_MAX_PRIVATE_EVENT_BYTES, MKT_MAX_PROFILES,
        MKT_MAX_RECEIPT_CONTENT_BYTES, MKT_MAX_REFERENCES, MKT_MAX_TAGS, MKT_OFFERING_KIND,
        MKT_OFFERING_STATUSES, MKT_ORDER_KIND, MKT_OUTCOMES, MKT_PROFILE_DESCRIPTOR_KIND,
        MKT_PROVIDER_PROFILE_KIND, MKT_PROVIDER_STATUSES, MKT_PUBLIC_RECEIPT_KIND,
        MKT_PUBLIC_RECEIPT_OUTCOMES, MKT_QUOTE_CLASSES, MKT_QUOTE_KIND, MKT_RELAY_PROFILES,
        MKT_RESERVATION_CLASSES, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_STATUS_STATES,
        MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND,
    },
    gateway::{
        GatewayLimits, MKT_GIFT_WRAP_RECIPIENT_RATE_EXCEEDED, MKT_PRIVATE_REQUIRES_GIFT_WRAP,
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
            crate_name: env!("CARGO_PKG_NAME"),
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
    let manifest = serde_json::from_str::<SourceManifest>(include_str!("../nips/manifest.json"))
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
                "private_key",
                "claim_private_key",
                "refund_private_key",
                "preimage",
                "macaroon",
                "nwc",
                "nwc_string",
                "musig_secret_nonce",
                "signing_nonce",
            ],
            upstream_fixture_cases: 70,
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
