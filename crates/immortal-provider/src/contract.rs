use std::{collections::BTreeSet, fmt};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const RUNTIME_FIXTURE_PATH: &str = "tests/fixtures/provider/provider-runtime-v1.json";
const RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/provider-runtime-v1.json");
const QUOTE_FIXTURE_PATH: &str = "tests/fixtures/provider/quote-builder-v1.json";
const QUOTE_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/quote-builder-v1.json");
const SETTLEMENT_FIXTURE_PATH: &str = "tests/fixtures/provider/settlement-construction-v1.json";
const SETTLEMENT_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/settlement-construction-v1.json");
const FUNDED_SMOKE_FIXTURE_PATH: &str = "tests/fixtures/provider/funded-smoke-v1.json";
const FUNDED_SMOKE_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/funded-smoke-v1.json");
const PRICING_FIXTURE_PATH: &str = "tests/fixtures/nipmkt/swp-pricing-v1.json";
const PRICING_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/nipmkt/swp-pricing-v1.json");
const COOPERATIVE_RUNTIME_FIXTURE_PATH: &str =
    "tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json";
const COOPERATIVE_RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json");
const LND_FIXTURE_PATH: &str = "tests/fixtures/provider/lnd-rest-v1.json";
const LND_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/provider/lnd-rest-v1.json");
const BOLTZ_API_FIXTURE_PATH: &str = "tests/fixtures/nipmkt/boltz-provider-api-v1.json";
const BOLTZ_API_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json");
const ADVERSARIAL_LAB_FIXTURE_PATH: &str = "tests/fixtures/lab/adversarial-v1.json";
const ADVERSARIAL_LAB_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/lab/adversarial-v1.json");
const CLN_ADVERSARIAL_HOLD_FIXTURE_PATH: &str =
    "tests/fixtures/provider/cln-adversarial-hold-v1.json";
const CLN_ADVERSARIAL_HOLD_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/cln-adversarial-hold-v1.json");
const DIRECT_RECOVERY_FIXTURE_PATH: &str = "tests/fixtures/provider/direct-recovery-v1.json";
const DIRECT_RECOVERY_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/direct-recovery-v1.json");
pub(crate) const BOLTZ_CONFIGURATION_SCHEMA: &str = concat!(
    "openagents.mkt-swp.boltz-provider-api.config.v1\n",
    "activation=exact_fixture_digest_private_bind_and_exact_browser_origin\n",
    "native_session=existing_signed_records_only\n",
    "submarine_create=rfq_quote_order_before_funding_prepare\n",
    "submarine_finalize=bilateral_contract_before_broadcast\n",
    "client_authorization=restored_snapshot_receipt_before_broadcast\n",
    "broadcast=session_bound\n",
    "preimage=public_claim_transaction_only\n",
    "nip11_advertisement=never\n",
);

pub fn boltz_provider_conformance_sha256() -> String {
    let mut digest = Sha256::new();
    digest.update(b"openagents.mkt-swp.boltz-provider-api.conformance.v1\0");
    digest.update(BOLTZ_API_FIXTURE);
    digest.update(b"\0");
    digest.update(BOLTZ_CONFIGURATION_SCHEMA.as_bytes());
    lower_hex(&digest.finalize())
}
const NIP_MANIFEST: &str = include_str!("../../../nips/manifest.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderContractError {
    NonCanonicalNumber,
    Serialization,
    ForbiddenCustodyMember,
    ConfiguredValuePresent,
    SecretEnvironmentNotMarked,
    InvalidShape,
}

impl fmt::Display for ProviderContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NonCanonicalNumber => "provider contract contains a non-integer number",
            Self::Serialization => "provider contract could not be serialized",
            Self::ForbiddenCustodyMember => "provider contract contains a custody-material member",
            Self::ConfiguredValuePresent => {
                "provider contract contains a configured environment value"
            }
            Self::SecretEnvironmentNotMarked => {
                "provider contract does not mark a secret environment name"
            }
            Self::InvalidShape => "provider contract has an invalid shape",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProviderContractError {}

pub fn provider_contract_value() -> Result<Value, ProviderContractError> {
    let contract = json!({
        "schema":"openagents.immortal.provider-contract.v1",
        "contract_version":1,
        "identity":{
            "product":"immortal-provider",
            "binary":"immortal-provider",
            "crate_name":env!("CARGO_CRATE_NAME"),
            "crate_version":env!("CARGO_PKG_VERSION"),
            "build_profile":"default_features",
            "modes":["funded","no_spend"],
            "commands":["run","address","contract","--no-spend"],
            "one_binary_per_product":true,
            "one_postgres_per_product":true,
            "nips":nip_sources()?
        },
        "modes":{
            "funded":{
                "custody_bearing":true,
                "rail_access":true,
                "prerequisites":["postgres","bitcoind","configured_lightning_rail"]
            },
            "no_spend":{
                "custody_bearing":false,
                "rail_access":false,
                "prerequisites":["relay"]
            }
        },
        "rails":{
            "bitcoind":{
                "required_in_modes":["funded"],
                "transport":"bounded_http_1_1_json_rpc",
                "network_scope":"resolved_and_connected_loopback_only",
                "authentication":"basic",
                "polling":{
                    "enabled":true,
                    "methods":["getbestblockhash","getblockheader","getrawmempool","gettxout"],
                    "bounded_backoff":true,
                    "staleness_is_failure":true,
                    "zmq":false
                },
                "runtime_methods":{
                    "quote_and_safety_height":["getblockchaininfo","estimatesmartfee"],
                    "transaction_observation":["getrawtransaction","gettxspendingprevout"],
                    "wallet_discovery":["scantxoutset"],
                    "execution":["sendrawtransaction"]
                }
            },
            "cln":{
                "selected_by":"IMMORTAL_PROVIDER_LIGHTNING_RAIL=cln",
                "transport":"bounded_newline_json_rpc_over_unix_socket",
                "one_request_per_connection":true,
                "startup_probe_method":"help",
                "required_capabilities":[
                    "holdinvoice",
                    "listholdinvoices",
                    "settleholdinvoice",
                    "cancelholdinvoice",
                    "invoice",
                    "pay",
                    "listinvoices",
                    "listpays",
                    "listfunds",
                    "getinfo"
                ],
                "hold_invoice_policy":{
                    "production":{
                        "rpc_method":"holdinvoice",
                        "explicit_expiry_policy":false,
                        "image":"scripts/support/provider-funded/Dockerfile.cln-hold"
                    },
                    "regtest_adversarial":{
                        "network":"regtest",
                        "rpc_method":"holdinvoiceimmortalregtest",
                        "startup_capability_required":true,
                        "expiry_seconds":30,
                        "minimum_final_cltv_delta":80,
                        "image":"scripts/support/provider-funded/Dockerfile.cln-hold-adversarial",
                        "source_fixture":"tests/fixtures/provider/cln-adversarial-hold-v1.json"
                    }
                },
                "quote_height_sync":{
                    "attempts_per_pass":40,
                    "delay_milliseconds":250,
                    "maximum_lag":"configured_reorg_safety_blocks",
                    "unsynchronized_action":"defer_quote",
                    "network_mismatch_action":"fail_closed"
                }
            },
            "lnd":{
                "available_with_feature":"lnd",
                "selected_by":"IMMORTAL_PROVIDER_LIGHTNING_RAIL=lnd",
                "transport":"bounded_http_1_1_rest_over_operator_pinned_tls",
                "network_scope":"resolved_and_connected_loopback_only",
                "authentication":"separate_mode_0600_readonly_invoice_router_macaroons",
                "redirects":false,
                "one_request_per_connection":true,
                "required_operations":[
                    "getinfo",
                    "listchannels",
                    "addholdinvoice",
                    "lookupinvoice",
                    "settleinvoice",
                    "cancelinvoice",
                    "sendpaymentv2",
                    "trackpaymentv2",
                    "registerblockepochntfn"
                ],
                "quote_height_sync":{
                    "attempts_per_pass":40,
                    "delay_milliseconds":250,
                    "maximum_lag":"configured_reorg_safety_blocks",
                    "unsynchronized_action":"defer_quote",
                    "network_mismatch_action":"fail_closed"
                }
            }
        },
        "execution":{
            "taproot_script_path":true,
            "musig2_key_path":false,
            "musig2_key_path_signer":false,
            "funding_before_bilateral_contract":false,
            "reverse_funding_transaction_precommitted_before_requester_payment":true,
            "chain_observation_requires_exact_committed_funding_bytes":true,
            "unresolved_state_is_success":false
        },
        "limits":limits_contract(),
        "vocabulary":{
            "close_outcomes":[
                "completed",
                "refunded",
                "cancelled",
                "rejected",
                "expired",
                "failed",
                "disputed",
                "unresolved"
            ],
            "funded_terminal_outcomes":["completed","refunded"],
            "failure_dispositions":[
                "invalid_hold_invoice",
                "hold_invoice_cancelled",
                "invalid_hold_invoice_settled",
                "hold_invoice_settled_before_funding",
                "lock_deadline_expired",
                "funding_deadline_expired",
                "claim_deadline_expired",
                "swp_reservation_overallocated",
                "quote_rejected"
            ],
            "provider_close_dispositions":[
                "provider_close_completed",
                "provider_close_refunded",
                "provider_close_cancelled",
                "provider_close_rejected",
                "provider_close_expired",
                "provider_close_failed",
                "provider_close_disputed",
                "provider_close_unresolved"
            ],
            "effect_states":["pending","applied","unresolved"],
            "reservation_states":["active","released","unresolved"],
            "watch_states":[
                "pending",
                "running",
                "broadcast",
                "confirmed",
                "completed",
                "unresolved",
                "page"
            ],
            "refund_watch_completion_reasons":["claim_settled"]
        },
        "configuration":{
            "source":"environment",
            "configured_values_exported":false,
            "variables":environment_contract()
        },
        "operations":{
            "address":{
                "requires":["bitcoin_network","wallet_seed_file"],
                "database_access":false,
                "rail_access":false,
                "output":"bip86_receive_address"
            },
            "contract":{
                "configuration_access":false,
                "custody_access":false,
                "output":"canonical_provider_contract_v1"
            },
            "health":{
                "transport":"plaintext_http",
                "network_scope":"private_or_loopback",
                "public_bind_allowed":false
            },
            "metrics":{
                "transport":"plaintext_http",
                "network_scope":"private_or_loopback",
                "public_bind_allowed":false
            },
            "direct_recovery":{
                "enabled_by_default":false,
                "required_mode":"funded",
                "activation":"IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND",
                "transport":"bounded_length_prefixed_json_over_private_tcp",
                "payload":"nip59_gift_wraps_only",
                "durable_sessions_only":true,
                "requires_bilateral_swap_contracts":true,
                "opens_new_sessions":false,
                "admits_pre_contract_negotiation":false,
                "persists_before_response":true,
                "terminal_history_replay":true,
                "nip11_advertised":false
            },
            "boltz_compatibility":{
                "enabled_by_default":false,
                "required_mode":"funded",
                "activation":"exact_conformance_digest_private_bind_and_exact_browser_origin",
                "mapping_revision":immortal_core::boltz_compat::BOLTZ_MAPPING_REVISION,
                "provider_process":true,
                "signed_native_session_source":true,
                "clean_room_client_seams":true,
                "pinned_upstream_client_builds":false,
                "fresh_client_engine_sessions":true,
                "session_bound_broadcast":true,
                "relay_body_access":false,
                "nip11_advertised":false,
                "endpoint_surface_emulated_routes":17,
                "endpoint_surface_route_denominator":53,
                "dependent_call_emulated_routes":19,
                "dependent_call_route_denominator":19,
                "requester_exit_package_modes":["presigned","wallet_sign"],
                "conformance_sha256":boltz_provider_conformance_sha256()
            },
            "alerts":{
                "transport":"plaintext_http",
                "network_scope":"private_numeric_or_loopback",
                "public_destination_allowed":false,
                "https_supported":false,
                "limitation":"v1_seven_dependency_allowlist"
            }
        },
        "custody":{
            "wallet":{
                "path_environment":"IMMORTAL_PROVIDER_WALLET_SEED_FILE",
                "required_file_mode":"0600",
                "regular_file_only":true,
                "symlink_allowed":false,
                "stored_in_database":false
            },
            "provider_database":{
                "stores_public_commitments_and_execution_state":true,
                "custody_exclusions":[
                    "wallet_seed",
                    "spend_key",
                    "claim_key",
                    "refund_key",
                    "unreleased_preimage",
                    "node_credential",
                    "rpc_password"
                ]
            },
            "logs_and_metrics_include_custody_material":false,
            "relay_receives_custody_material":false
        },
        "v1_exclusions":[
            "zmq",
            "musig2_automated_actor_path",
            "outbound_https_price_feeds",
            "liquid",
            "ark",
            "evm",
            "cashu",
            "autoswap_inventory_strategy"
        ],
        "fixtures":{
            "algorithm":"sha256",
            "entries":[
                fixture_entry(RUNTIME_FIXTURE_PATH, RUNTIME_FIXTURE),
                fixture_entry(QUOTE_FIXTURE_PATH, QUOTE_FIXTURE),
                fixture_entry(SETTLEMENT_FIXTURE_PATH, SETTLEMENT_FIXTURE),
                fixture_entry(FUNDED_SMOKE_FIXTURE_PATH, FUNDED_SMOKE_FIXTURE),
                fixture_entry(PRICING_FIXTURE_PATH, PRICING_FIXTURE),
                fixture_entry(COOPERATIVE_RUNTIME_FIXTURE_PATH, COOPERATIVE_RUNTIME_FIXTURE),
                fixture_entry(LND_FIXTURE_PATH, LND_FIXTURE),
                fixture_entry(BOLTZ_API_FIXTURE_PATH, BOLTZ_API_FIXTURE),
                fixture_entry(ADVERSARIAL_LAB_FIXTURE_PATH, ADVERSARIAL_LAB_FIXTURE),
                fixture_entry(CLN_ADVERSARIAL_HOLD_FIXTURE_PATH, CLN_ADVERSARIAL_HOLD_FIXTURE),
                fixture_entry(DIRECT_RECOVERY_FIXTURE_PATH, DIRECT_RECOVERY_FIXTURE)
            ]
        },
        "relay_contract_affected":false,
        "nip11_affected":false
    });
    validate_provider_contract(&contract)?;
    Ok(contract)
}

#[cfg(feature = "funded")]
fn limits_contract() -> Value {
    json!({
        "relay_actor":{
            "message_bytes":crate::relay_actor::MAX_RELAY_MESSAGE_BYTES,
            "history_wraps":crate::relay_actor::MAX_HISTORY_WRAPS,
            "active_sessions_global":crate::relay_actor::MAX_SESSIONS,
            "active_sessions_per_requester":crate::relay_actor::MAX_SESSIONS_PER_REQUESTER,
            "reconnect_attempts":crate::relay_actor::MAX_RECONNECT_ATTEMPTS,
            "actions_per_advance":crate::relay_actor::MAX_ACTIONS_PER_ADVANCE
        },
        "session":{
            "records":crate::session::MAX_PROVIDER_RECORDS,
            "effects":crate::session::MAX_PROVIDER_EFFECTS,
            "snapshot_bytes":crate::session::MAX_PROVIDER_SNAPSHOT_BYTES
        },
        "rail_rpc":{
            "bitcoind":{
                "header_bytes":crate::bitcoind::DEFAULT_MAX_HEADER_BYTES,
                "request_bytes":crate::bitcoind::DEFAULT_MAX_REQUEST_BYTES,
                "response_bytes":crate::bitcoind::DEFAULT_MAX_RESPONSE_BYTES,
                "resolved_addresses":crate::bitcoind::MAX_RESOLVED_ADDRESSES
            },
            "cln":{
                "request_bytes":crate::cln::DEFAULT_MAX_REQUEST_BYTES,
                "response_bytes":crate::cln::DEFAULT_MAX_RESPONSE_BYTES
            },
            "lnd":{
                "header_bytes":16384,
                "request_bytes":1048576,
                "response_bytes":8388608,
                "stream_messages":64,
                "resolved_addresses":8
            }
        },
        "store":{
            "records_per_session":crate::store::MAX_SESSION_RECORDS,
            "session_query":crate::store::MAX_SESSION_QUERY,
            "session_batch":crate::store::MAX_SESSION_BATCH,
            "active_session_record_query":crate::store::MAX_ACTIVE_SESSION_RECORD_QUERY,
            "reservation_utxos":crate::store::MAX_RESERVATION_UTXOS,
            "watch_claim":crate::store::MAX_WATCH_CLAIM,
            "alert_query":crate::store::MAX_ALERT_QUERY,
            "json_bytes":crate::store::MAX_JSON_BYTES,
            "health_count_scan":crate::store::HEALTH_COUNT_SCAN_LIMIT
        },
        "watchtower":{
            "raw_transaction_bytes":crate::watchtower::MAX_RAW_TRANSACTION_BYTES,
            "inputs":crate::watchtower::MAX_WATCH_INPUTS,
            "due_jobs_per_pass":crate::watchtower::MAX_DUE_JOBS,
            "observation_jobs_per_pass":crate::watchtower::MAX_OBSERVATION_JOBS,
            "alerts_per_pass":crate::watchtower::MAX_ALERTS,
            "mempool_transactions":crate::watchtower::MAX_MEMPOOL_TRANSACTIONS,
            "watch_attempts":crate::funded_mode::MAXIMUM_WATCH_ATTEMPTS,
            "poll_failures":crate::watchtower::MAX_POLL_FAILURES,
            "lease_seconds":crate::watchtower::WATCH_LEASE_SECONDS
        },
        "health":{
            "connections":crate::health::MAX_HEALTH_CONNECTIONS,
            "request_bytes":crate::health::MAX_HTTP_REQUEST_BYTES,
            "alert_response_bytes":crate::health::MAX_ALERT_RESPONSE_BYTES
        },
        "direct_recovery":{
            "request_bytes":crate::direct_recovery::MAX_REQUEST_BYTES,
            "response_bytes":crate::direct_recovery::MAX_RESPONSE_BYTES,
            "request_wraps":crate::direct_recovery::MAX_REQUEST_WRAPS,
            "response_wraps":crate::direct_recovery::MAX_RESPONSE_WRAPS,
            "connections_per_poll":crate::direct_recovery::MAX_CONNECTIONS_PER_POLL,
            "connection_deadline_seconds":crate::direct_recovery::CONNECTION_TIMEOUT.as_secs()
        },
        "boltz_compatibility":{
            "connections":crate::boltz::MAX_CONNECTIONS,
            "requests_per_minute_per_ip":crate::boltz::MAX_REQUESTS_PER_MINUTE,
            "http_head_bytes":crate::boltz::MAX_HTTP_HEAD_BYTES,
            "json_body_bytes":crate::boltz::MAX_JSON_BODY_BYTES,
            "raw_transaction_bytes":crate::boltz::MAX_RAW_TRANSACTION_BYTES,
            "status_ids":crate::boltz::MAX_STATUS_IDS,
            "websocket_subscriptions":crate::boltz::MAX_WS_SUBSCRIPTIONS,
            "websocket_frame_bytes":crate::boltz::MAX_WS_FRAME_BYTES,
            "websocket_messages_per_minute_per_ip":crate::boltz::MAX_WS_MESSAGES_PER_MINUTE,
            "websocket_status_query_batches_per_minute_per_ip":crate::boltz::MAX_WS_STATUS_QUERY_BATCHES_PER_MINUTE,
            "websocket_poll_interval_milliseconds":crate::boltz::WS_POLL_INTERVAL.as_millis(),
            "connection_deadline_seconds":crate::boltz::REQUEST_TIMEOUT.as_secs(),
            "websocket_idle_deadline_seconds":crate::boltz::WS_IDLE_TIMEOUT.as_secs(),
            "websocket_frame_completion_deadline_seconds":crate::boltz::REQUEST_TIMEOUT.as_secs()
        },
        "quote":{
            "rail_sync_attempts":crate::funded_mode::QUOTE_RAIL_SYNC_ATTEMPTS,
            "rail_sync_delay_milliseconds":crate::funded_mode::QUOTE_RAIL_SYNC_DELAY.as_millis(),
            "invoice_expiry_seconds":crate::quote::MAX_INVOICE_SECONDS,
            "spread_bps_maximum":crate::pricing::MAX_SPREAD_BPS,
            "feerate_sat_per_vbyte_maximum":crate::pricing::MAX_FEERATE_SAT_PER_VB,
            "swap_sat_maximum":crate::pricing::MAX_AMOUNT_SAT,
            "validity_seconds_maximum":crate::pricing::MAX_QUOTE_EXPIRY_SECONDS,
            "lightning_routing_fee_ppm_maximum":crate::pricing::MAX_LIGHTNING_ROUTING_FEE_PPM
        }
    })
}

#[cfg(not(feature = "funded"))]
fn limits_contract() -> Value {
    json!({
        "relay_actor":{
            "message_bytes":524288,
            "history_wraps":120,
            "active_sessions_global":12,
            "active_sessions_per_requester":4,
            "reconnect_attempts":8,
            "actions_per_advance":16
        },
        "session":{"records":512,"effects":128,"snapshot_bytes":2097152},
        "rail_rpc":{
            "bitcoind":{
                "header_bytes":16384,
                "request_bytes":4194304,
                "response_bytes":16777216,
                "resolved_addresses":8
            },
            "cln":{"request_bytes":1048576,"response_bytes":8388608},
            "lnd":{"header_bytes":16384,"request_bytes":1048576,"response_bytes":8388608,"stream_messages":64,"resolved_addresses":8}
        },
        "store":{
            "records_per_session":512,
            "session_query":512,
            "session_batch":64,
            "active_session_record_query":6144,
            "reservation_utxos":64,
            "watch_claim":64,
            "alert_query":128,
            "json_bytes":1048576,
            "health_count_scan":10001
        },
        "watchtower":{
            "raw_transaction_bytes":1000000,
            "inputs":4096,
            "due_jobs_per_pass":32,
            "observation_jobs_per_pass":64,
            "alerts_per_pass":64,
            "mempool_transactions":1000000,
            "watch_attempts":32,
            "poll_failures":8,
            "lease_seconds":30
        },
        "health":{"connections":16,"request_bytes":4096,"alert_response_bytes":65536},
        "direct_recovery":{"request_bytes":2097152,"response_bytes":8388608,"request_wraps":32,"response_wraps":512,"connections_per_poll":4,"connection_deadline_seconds":5},
        "boltz_compatibility":{
            "connections":64,
            "requests_per_minute_per_ip":120,
            "http_head_bytes":16384,
            "json_body_bytes":2000128,
            "raw_transaction_bytes":1000000,
            "status_ids":64,
            "websocket_subscriptions":64,
            "websocket_frame_bytes":16384,
            "websocket_messages_per_minute_per_ip":120,
            "websocket_status_query_batches_per_minute_per_ip":60,
            "websocket_poll_interval_milliseconds":1000,
            "connection_deadline_seconds":10,
            "websocket_idle_deadline_seconds":90,
            "websocket_frame_completion_deadline_seconds":10
        },
        "quote":{
            "rail_sync_attempts":40,
            "rail_sync_delay_milliseconds":250,
            "invoice_expiry_seconds":31536000,
            "spread_bps_maximum":1000,
            "feerate_sat_per_vbyte_maximum":2000,
            "swap_sat_maximum":2100000000000000_u64,
            "validity_seconds_maximum":3600,
            "lightning_routing_fee_ppm_maximum":100000
        }
    })
}

fn fixture_entry(path: &'static str, bytes: &[u8]) -> Value {
    json!({
        "path":path,
        "bytes":bytes.len(),
        "sha256":lower_hex(&Sha256::digest(bytes))
    })
}

pub fn provider_contract_bytes() -> Result<Vec<u8>, ProviderContractError> {
    let mut bytes = canonical_json(&provider_contract_value()?)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn provider_contract_sha256() -> Result<String, ProviderContractError> {
    Ok(lower_hex(&Sha256::digest(provider_contract_bytes()?)))
}

pub fn validate_provider_contract(value: &Value) -> Result<(), ProviderContractError> {
    reject_forbidden_members(value)?;
    let root = value
        .as_object()
        .ok_or(ProviderContractError::InvalidShape)?;
    let expected_root_keys = BTreeSet::from([
        "schema",
        "contract_version",
        "identity",
        "modes",
        "rails",
        "execution",
        "limits",
        "vocabulary",
        "configuration",
        "operations",
        "custody",
        "v1_exclusions",
        "fixtures",
        "relay_contract_affected",
        "nip11_affected",
    ]);
    if root.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_root_keys {
        return Err(ProviderContractError::InvalidShape);
    }
    if root.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.provider-contract.v1")
        || root.get("contract_version").and_then(Value::as_u64) != Some(1)
        || root.get("relay_contract_affected").and_then(Value::as_bool) != Some(false)
        || root.get("nip11_affected").and_then(Value::as_bool) != Some(false)
        || root
            .get("configuration")
            .and_then(Value::as_object)
            .and_then(|configuration| configuration.get("configured_values_exported"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(ProviderContractError::InvalidShape);
    }
    validate_limits(
        root.get("limits")
            .ok_or(ProviderContractError::InvalidShape)?,
    )?;
    validate_vocabulary(
        root.get("vocabulary")
            .ok_or(ProviderContractError::InvalidShape)?,
    )?;
    let identity = root
        .get("identity")
        .and_then(Value::as_object)
        .ok_or(ProviderContractError::InvalidShape)?;
    if identity.get("crate_name").and_then(Value::as_str) != Some(env!("CARGO_CRATE_NAME"))
        || identity.get("crate_version").and_then(Value::as_str) != Some(env!("CARGO_PKG_VERSION"))
        || identity.get("build_profile").and_then(Value::as_str) != Some("default_features")
    {
        return Err(ProviderContractError::InvalidShape);
    }
    let configured_nips = identity
        .get("nips")
        .ok_or(ProviderContractError::InvalidShape)?;
    validate_nip_sources(configured_nips)?;
    if configured_nips != &nip_sources()? {
        return Err(ProviderContractError::InvalidShape);
    }
    let variables = root
        .get("configuration")
        .and_then(Value::as_object)
        .and_then(|configuration| configuration.get("variables"))
        .and_then(Value::as_array)
        .ok_or(ProviderContractError::InvalidShape)?;
    let mut names = BTreeSet::new();
    for variable in variables {
        let variable = variable
            .as_object()
            .ok_or(ProviderContractError::InvalidShape)?;
        if variable.contains_key("value")
            || variable.contains_key("default")
            || variable.contains_key("default_value")
        {
            return Err(ProviderContractError::ConfiguredValuePresent);
        }
        let name = variable
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ProviderContractError::InvalidShape)?;
        if !names.insert(name)
            || !name.starts_with("IMMORTAL_PROVIDER_")
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !valid_mode_scope(variable)
            || !valid_lightning_environment_contract(name, variable)
        {
            return Err(ProviderContractError::InvalidShape);
        }
        if environment_name_is_secret(name)
            && variable.get("secret").and_then(Value::as_bool) != Some(true)
        {
            return Err(ProviderContractError::SecretEnvironmentNotMarked);
        }
        match variable.get("type").and_then(Value::as_str) {
            Some("string") if valid_bounds(variable, "minimum_bytes", "maximum_bytes") => {}
            Some("integer") if valid_bounds(variable, "minimum", "maximum") => {}
            Some("choice")
                if variable
                    .get("choices")
                    .and_then(Value::as_array)
                    .is_some_and(|choices| !choices.is_empty()) => {}
            _ => return Err(ProviderContractError::InvalidShape),
        }
    }
    Ok(())
}

fn validate_limits(value: &Value) -> Result<(), ProviderContractError> {
    if value != &limits_contract() {
        return Err(ProviderContractError::InvalidShape);
    }
    let limits = value
        .as_object()
        .ok_or(ProviderContractError::InvalidShape)?;
    let expected_sections = BTreeSet::from([
        "relay_actor",
        "session",
        "rail_rpc",
        "store",
        "watchtower",
        "health",
        "direct_recovery",
        "boltz_compatibility",
        "quote",
    ]);
    if limits.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_sections
        || !limits.values().all(positive_limit_tree)
    {
        return Err(ProviderContractError::InvalidShape);
    }
    let relay = limits
        .get("relay_actor")
        .and_then(Value::as_object)
        .ok_or(ProviderContractError::InvalidShape)?;
    let expected_relay_keys = BTreeSet::from([
        "message_bytes",
        "history_wraps",
        "active_sessions_global",
        "active_sessions_per_requester",
        "reconnect_attempts",
        "actions_per_advance",
    ]);
    let active_global = relay
        .get("active_sessions_global")
        .and_then(Value::as_u64)
        .ok_or(ProviderContractError::InvalidShape)?;
    let active_per_requester = relay
        .get("active_sessions_per_requester")
        .and_then(Value::as_u64)
        .ok_or(ProviderContractError::InvalidShape)?;
    if relay.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_relay_keys
        || active_per_requester != 4
        || active_per_requester > active_global
    {
        return Err(ProviderContractError::InvalidShape);
    }
    Ok(())
}

fn positive_limit_tree(value: &Value) -> bool {
    match value {
        Value::Object(object) => !object.is_empty() && object.values().all(positive_limit_tree),
        Value::Number(number) => number.as_u64().is_some_and(|number| number > 0),
        _ => false,
    }
}

fn validate_vocabulary(value: &Value) -> Result<(), ProviderContractError> {
    let vocabulary = value
        .as_object()
        .ok_or(ProviderContractError::InvalidShape)?;
    let expected_keys = BTreeSet::from([
        "close_outcomes",
        "funded_terminal_outcomes",
        "failure_dispositions",
        "provider_close_dispositions",
        "effect_states",
        "reservation_states",
        "watch_states",
        "refund_watch_completion_reasons",
    ]);
    if vocabulary
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_keys
    {
        return Err(ProviderContractError::InvalidShape);
    }
    let expected_failure_dispositions = [
        "invalid_hold_invoice",
        "hold_invoice_cancelled",
        "invalid_hold_invoice_settled",
        "hold_invoice_settled_before_funding",
        "lock_deadline_expired",
        "funding_deadline_expired",
        "claim_deadline_expired",
        "swp_reservation_overallocated",
        "quote_rejected",
    ];
    if vocabulary
        .get("failure_dispositions")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .as_deref()
        != Some(expected_failure_dispositions.as_slice())
    {
        return Err(ProviderContractError::InvalidShape);
    }
    for values in vocabulary.values() {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or(ProviderContractError::InvalidShape)?;
        let mut unique = BTreeSet::new();
        for value in values {
            let value = value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'_' | b'-' | b'.')
                        })
                })
                .ok_or(ProviderContractError::InvalidShape)?;
            if !unique.insert(value) {
                return Err(ProviderContractError::InvalidShape);
            }
        }
    }
    Ok(())
}

fn nip_sources() -> Result<Value, ProviderContractError> {
    let manifest: Value =
        serde_json::from_str(NIP_MANIFEST).map_err(|_| ProviderContractError::InvalidShape)?;
    let sources = manifest
        .get("sources")
        .and_then(Value::as_array)
        .ok_or(ProviderContractError::InvalidShape)?;
    let expected = ["official", "block", "openagents"];
    if sources.len() != expected.len() {
        return Err(ProviderContractError::InvalidShape);
    }
    let mut identity = Vec::with_capacity(expected.len());
    for (source, expected_lane) in sources.iter().zip(expected) {
        let source = source
            .as_object()
            .ok_or(ProviderContractError::InvalidShape)?;
        let lane = source
            .get("name")
            .and_then(Value::as_str)
            .filter(|lane| *lane == expected_lane)
            .ok_or(ProviderContractError::InvalidShape)?;
        let repo = source
            .get("repo")
            .and_then(Value::as_str)
            .filter(|repo| repo.starts_with("https://github.com/") && repo.len() <= 256)
            .ok_or(ProviderContractError::InvalidShape)?;
        let subdir = source
            .get("subdir")
            .and_then(Value::as_str)
            .filter(|subdir| !subdir.is_empty() && subdir.len() <= 128)
            .ok_or(ProviderContractError::InvalidShape)?;
        let commit = source
            .get("commit")
            .and_then(Value::as_str)
            .filter(|commit| valid_commit(commit))
            .ok_or(ProviderContractError::InvalidShape)?;
        identity.push(json!({
            "lane":lane,
            "repo":repo,
            "subdir":subdir,
            "commit":commit
        }));
    }
    let value = Value::Array(identity);
    validate_nip_sources(&value)?;
    Ok(value)
}

fn validate_nip_sources(value: &Value) -> Result<(), ProviderContractError> {
    let sources = value
        .as_array()
        .filter(|sources| sources.len() == 3)
        .ok_or(ProviderContractError::InvalidShape)?;
    for (source, expected_lane) in sources.iter().zip(["official", "block", "openagents"]) {
        let source = source
            .as_object()
            .ok_or(ProviderContractError::InvalidShape)?;
        if source.len() != 4
            || source.get("lane").and_then(Value::as_str) != Some(expected_lane)
            || !source
                .get("repo")
                .and_then(Value::as_str)
                .is_some_and(|repo| repo.starts_with("https://github.com/") && repo.len() <= 256)
            || !source
                .get("subdir")
                .and_then(Value::as_str)
                .is_some_and(|subdir| !subdir.is_empty() && subdir.len() <= 128)
            || !source
                .get("commit")
                .and_then(Value::as_str)
                .is_some_and(valid_commit)
        {
            return Err(ProviderContractError::InvalidShape);
        }
    }
    Ok(())
}

fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn environment_contract() -> Value {
    json!([
        env_string(
            "IMMORTAL_PROVIDER_DATABASE_URL",
            &["funded"],
            1,
            4096,
            true,
            None
        ),
        env_string(
            "IMMORTAL_PROVIDER_RELAY_URL",
            &["funded", "no_spend"],
            1,
            2048,
            false,
            Some("loopback_plaintext_websocket_url")
        ),
        env_string(
            "IMMORTAL_PROVIDER_IDENTITY_SECRET",
            &["funded", "no_spend"],
            64,
            64,
            true,
            Some("lowercase_hex")
        ),
        env_choice(
            "IMMORTAL_PROVIDER_BITCOIN_NETWORK",
            &["funded"],
            &["mainnet", "testnet", "signet", "regtest"]
        ),
        lab_profile_environment(),
        lab_cooperative_signing_environment(),
        env_string(
            "IMMORTAL_PROVIDER_BITCOIND_HOST",
            &["funded"],
            1,
            253,
            false,
            Some("loopback_host")
        ),
        env_integer("IMMORTAL_PROVIDER_BITCOIND_PORT", &["funded"], 1, 65535),
        env_string(
            "IMMORTAL_PROVIDER_BITCOIND_RPC_USER",
            &["funded"],
            1,
            256,
            true,
            None
        ),
        env_string(
            "IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD",
            &["funded"],
            1,
            1024,
            true,
            None
        ),
        lightning_selector_environment(),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_CLN_RPC_PATH",
                &["funded"],
                1,
                4096,
                true,
                Some("absolute_unix_socket_path"),
                false
            ),
            "cln",
            true
        ),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_LND_HOST",
                &["funded"],
                1,
                253,
                false,
                Some("loopback_host"),
                false
            ),
            "lnd",
            false
        ),
        conditional_lightning_environment(
            optional_env_integer_without_default(
                "IMMORTAL_PROVIDER_LND_PORT",
                &["funded"],
                1,
                65535
            ),
            "lnd",
            false
        ),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_LND_TLS_CERT_FILE",
                &["funded"],
                1,
                4096,
                false,
                Some("absolute_regular_file"),
                false
            ),
            "lnd",
            false
        ),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE",
                &["funded"],
                1,
                4096,
                true,
                Some("absolute_mode_0600_regular_file"),
                false
            ),
            "lnd",
            false
        ),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE",
                &["funded"],
                1,
                4096,
                true,
                Some("absolute_mode_0600_regular_file"),
                false
            ),
            "lnd",
            false
        ),
        conditional_lightning_environment(
            optional_env_string(
                "IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE",
                &["funded"],
                1,
                4096,
                true,
                Some("absolute_mode_0600_regular_file"),
                false
            ),
            "lnd",
            false
        ),
        env_string(
            "IMMORTAL_PROVIDER_WALLET_SEED_FILE",
            &["funded"],
            1,
            4096,
            true,
            Some("absolute_mode_0600_regular_file")
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_HEALTH_BIND",
            &["funded"],
            1,
            128,
            false,
            Some("private_or_loopback_socket_address"),
            true
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND",
            &["funded"],
            1,
            128,
            false,
            Some("private_or_loopback_socket_address"),
            false
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_ALERT_URL",
            &["funded"],
            1,
            2048,
            false,
            Some("private_numeric_plaintext_http_url"),
            false
        ),
        optional_env_integer("IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS", &["funded"], 1, 300),
        optional_env_integer(
            "IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS",
            &["funded"],
            5,
            3600
        ),
        optional_env_integer(
            "IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS",
            &["funded"],
            1,
            144
        ),
        optional_env_integer("IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS", &["funded"], 1, 144),
        optional_env_integer("IMMORTAL_PROVIDER_SPREAD_BPS", &["funded"], 0, 1000),
        optional_env_integer_without_default(
            "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB",
            &["funded"],
            1,
            2000
        ),
        optional_env_integer(
            "IMMORTAL_PROVIDER_QUOTE_MIN_SAT",
            &["funded"],
            1,
            2100000000000000_u64
        ),
        optional_env_integer(
            "IMMORTAL_PROVIDER_QUOTE_MAX_SAT",
            &["funded"],
            1,
            2100000000000000_u64
        ),
        optional_env_integer(
            "IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS",
            &["funded"],
            1,
            3600
        ),
        optional_env_choice("IMMORTAL_PROVIDER_RESERVATION_TIER", &["funded"], &["hard"]),
        optional_env_integer(
            "IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM",
            &["funded"],
            0,
            100000
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_BOLTZ_BIND",
            &["funded"],
            1,
            128,
            false,
            Some("private_or_loopback_socket_address_required_with_boltz_profile"),
            false
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256",
            &["funded"],
            64,
            64,
            false,
            Some("exact_compiled_lowercase_sha256_required_with_boltz_profile"),
            false
        ),
        optional_env_string(
            "IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN",
            &["funded"],
            1,
            2048,
            false,
            Some("single_exact_http_or_https_origin_required_with_boltz_profile"),
            false
        )
    ])
}

fn env_string(
    name: &'static str,
    required_in_modes: &[&str],
    minimum_bytes: u64,
    maximum_bytes: u64,
    secret: bool,
    format: Option<&'static str>,
) -> Value {
    let mut value = json!({
        "name":name,
        "type":"string",
        "required_in_modes":required_in_modes,
        "minimum_bytes":minimum_bytes,
        "maximum_bytes":maximum_bytes,
        "secret":secret
    });
    if let Some(format) = format {
        value["format"] = Value::String(format.to_owned());
    }
    value
}

fn env_integer(
    name: &'static str,
    required_in_modes: &[&str],
    minimum: u64,
    maximum: u64,
) -> Value {
    json!({
        "name":name,
        "type":"integer",
        "required_in_modes":required_in_modes,
        "minimum":minimum,
        "maximum":maximum,
        "secret":false
    })
}

fn optional_env_string(
    name: &'static str,
    modes: &[&str],
    minimum_bytes: u64,
    maximum_bytes: u64,
    secret: bool,
    format: Option<&'static str>,
    defaulted: bool,
) -> Value {
    optional_environment(
        env_string(name, modes, minimum_bytes, maximum_bytes, secret, format),
        modes,
        defaulted,
    )
}

fn optional_env_integer(name: &'static str, modes: &[&str], minimum: u64, maximum: u64) -> Value {
    optional_environment(env_integer(name, modes, minimum, maximum), modes, true)
}

fn optional_env_integer_without_default(
    name: &'static str,
    modes: &[&str],
    minimum: u64,
    maximum: u64,
) -> Value {
    optional_environment(env_integer(name, modes, minimum, maximum), modes, false)
}

fn optional_env_choice(name: &'static str, modes: &[&str], choices: &[&str]) -> Value {
    optional_environment(env_choice(name, modes, choices), modes, true)
}

fn lightning_selector_environment() -> Value {
    let mut value = optional_env_choice(
        "IMMORTAL_PROVIDER_LIGHTNING_RAIL",
        &["funded"],
        &["cln", "lnd"],
    );
    value["implicit_choice_when_absent"] = Value::String("cln".to_owned());
    value
}

fn lab_profile_environment() -> Value {
    let mut value = optional_environment(
        env_choice(
            "IMMORTAL_PROVIDER_LAB_PROFILE",
            &["funded"],
            &["regtest_adversarial"],
        ),
        &["funded"],
        false,
    );
    value["required_network"] = Value::String("regtest".to_owned());
    value["quote_expiry_seconds"] = json!(3);
    value["hold_invoice_expiry_seconds"] = json!(30);
    value
}

fn lab_cooperative_signing_environment() -> Value {
    let mut value = optional_environment(
        env_choice(
            "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING",
            &["funded"],
            &["true"],
        ),
        &["funded"],
        false,
    );
    value["required_network"] = Value::String("regtest".to_owned());
    value["required_lab_profile"] = Value::String("regtest_adversarial".to_owned());
    value["lab_only"] = Value::Bool(true);
    value
}

fn conditional_lightning_environment(
    mut value: Value,
    choice: &'static str,
    selector_absent: bool,
) -> Value {
    value["required_when"] = json!({
        "environment":"IMMORTAL_PROVIDER_LIGHTNING_RAIL",
        "equals":choice,
        "or_selector_absent":selector_absent,
    });
    value
}

fn optional_environment(mut value: Value, modes: &[&str], defaulted: bool) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("required_in_modes");
        object.insert("optional_in_modes".to_owned(), json!(modes));
        object.insert("defaulted".to_owned(), Value::Bool(defaulted));
    }
    value
}

fn env_choice(name: &'static str, required_in_modes: &[&str], choices: &[&str]) -> Value {
    json!({
        "name":name,
        "type":"choice",
        "required_in_modes":required_in_modes,
        "choices":choices,
        "secret":false
    })
}

fn reject_forbidden_members(value: &Value) -> Result<(), ProviderContractError> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = normalize_name(name);
                if normalized.ends_with("seed")
                    || normalized.contains("secretkey")
                    || normalized.contains("privatekey")
                    || normalized.contains("spendkey")
                    || normalized.contains("claimkey")
                    || normalized.contains("refundkey")
                    || normalized.contains("preimage")
                    || normalized.contains("macaroon")
                    || normalized.contains("credentialvalue")
                    || normalized.contains("rpcpasswordvalue")
                {
                    return Err(ProviderContractError::ForbiddenCustodyMember);
                }
                reject_forbidden_members(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_forbidden_members(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn environment_name_is_secret(name: &str) -> bool {
    name.ends_with("_SECRET")
        || name.ends_with("_PASSWORD")
        || name.ends_with("_SEED")
        || name.ends_with("_SEED_FILE")
        || matches!(
            name,
            "IMMORTAL_PROVIDER_DATABASE_URL"
                | "IMMORTAL_PROVIDER_BITCOIND_RPC_USER"
                | "IMMORTAL_PROVIDER_CLN_RPC_PATH"
                | "IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE"
                | "IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE"
                | "IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE"
        )
}

fn valid_bounds(variable: &Map<String, Value>, minimum: &str, maximum: &str) -> bool {
    matches!(
        (
            variable.get(minimum).and_then(Value::as_u64),
            variable.get(maximum).and_then(Value::as_u64),
        ),
        (Some(minimum), Some(maximum)) if minimum <= maximum
    )
}

fn valid_mode_scope(variable: &Map<String, Value>) -> bool {
    let required = variable
        .get("required_in_modes")
        .and_then(Value::as_array)
        .is_some_and(|modes| !modes.is_empty());
    let optional = variable
        .get("optional_in_modes")
        .and_then(Value::as_array)
        .is_some_and(|modes| !modes.is_empty());
    required ^ optional
}

fn valid_lightning_environment_contract(name: &str, variable: &Map<String, Value>) -> bool {
    let implicit_choice = variable
        .get("implicit_choice_when_absent")
        .and_then(Value::as_str);
    let required_when = variable.get("required_when").and_then(Value::as_object);
    if name == "IMMORTAL_PROVIDER_LIGHTNING_RAIL" {
        return implicit_choice == Some("cln") && required_when.is_none();
    }
    let expected = if name == "IMMORTAL_PROVIDER_CLN_RPC_PATH" {
        Some(("cln", true))
    } else if matches!(
        name,
        "IMMORTAL_PROVIDER_LND_HOST"
            | "IMMORTAL_PROVIDER_LND_PORT"
            | "IMMORTAL_PROVIDER_LND_TLS_CERT_FILE"
            | "IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE"
            | "IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE"
            | "IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE"
    ) {
        Some(("lnd", false))
    } else {
        None
    };
    match (expected, required_when) {
        (None, None) => implicit_choice.is_none(),
        (Some((choice, selector_absent)), Some(condition)) => {
            implicit_choice.is_none()
                && condition.len() == 3
                && condition.get("environment").and_then(Value::as_str)
                    == Some("IMMORTAL_PROVIDER_LIGHTNING_RAIL")
                && condition.get("equals").and_then(Value::as_str) == Some(choice)
                && condition.get("or_selector_absent").and_then(Value::as_bool)
                    == Some(selector_absent)
        }
        _ => false,
    }
}

fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, ProviderContractError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), ProviderContractError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ProviderContractError::Serialization)?
                .as_bytes(),
        ),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(ProviderContractError::NonCanonicalNumber);
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
        Value::Object(values) => write_canonical_object(values, output)?,
    }
    Ok(())
}

fn write_canonical_object(
    values: &Map<String, Value>,
    output: &mut Vec<u8>,
) -> Result<(), ProviderContractError> {
    output.push(b'{');
    let mut members = values.iter().collect::<Vec<_>>();
    members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    for (index, (name, value)) in members.into_iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        output.extend_from_slice(
            serde_json::to_string(name)
                .map_err(|_| ProviderContractError::Serialization)?
                .as_bytes(),
        );
        output.push(b':');
        write_canonical_json(value, output)?;
    }
    output.push(b'}');
    Ok(())
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
