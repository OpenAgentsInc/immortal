use immortal_core::boltz_compat::{classify_boltz_handoff, safe_origin_form};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct Fixture {
    mapping_revision: String,
    source_pins: SourcePins,
    route_cases: Vec<RouteCase>,
    rejected_paths: Vec<String>,
    routes_outside_profile: Vec<OutsideProfile>,
    coverage: Coverage,
}

#[derive(Deserialize, PartialEq, Eq)]
struct SourcePins {
    boltz_client: String,
    boltz_web_app: String,
}

#[derive(Deserialize)]
struct RouteCase {
    method: String,
    path: String,
    class: String,
    callers: Vec<String>,
}

#[derive(Deserialize)]
struct OutsideProfile {
    method: String,
    path: String,
}

#[derive(Deserialize)]
struct Coverage {
    backend_v2_route_denominator: usize,
    endpoint_surface_emulated_routes: usize,
    dependent_call_route_denominator: usize,
    dependent_call_emulated_routes: usize,
    relay_redirect_routes_are_not_emulation: bool,
}

#[derive(Deserialize)]
struct AdapterFixture {
    mapping_revision: String,
    source_pins: SourcePins,
    funding_law: FundingLaw,
    released_union_route_shapes: Vec<String>,
    clients: AdapterClients,
    coverage: AdapterCoverage,
}

#[derive(Deserialize)]
struct FundingLaw {
    sequence: Vec<String>,
    requester_contract_required: bool,
    provider_contract_required: bool,
    contract_ids_are_finalize_callback_outputs: bool,
    exact_funding_binding_required: bool,
    persisted_script_path_exit_required: bool,
    restored_authorization_snapshot_sha256_required: bool,
    cooperative_endpoints_allowed: bool,
    one_shot_prepare_and_broadcast_allowed: bool,
    maximum_raw_transaction_bytes: usize,
}

#[derive(Deserialize)]
struct AdapterClients {
    go: AdapterClient,
    web: AdapterClient,
}

#[derive(Deserialize)]
struct AdapterClient {
    source: String,
    route_shapes: Vec<String>,
    forbidden_source_tokens: Vec<String>,
}

#[derive(Deserialize)]
struct AdapterCoverage {
    pinned_upstream_client_builds: bool,
    adapter_source_and_unit_gate: bool,
    provider_listener_process_gate: bool,
    fresh_client_engine_session_per_seam: bool,
    dependent_call_emulated_routes: usize,
    dependent_call_route_denominator: usize,
}

#[test]
fn released_client_handoff_fixture_replays_exact_route_classes() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/boltz-facade-v2.json"
    ))
    .expect("valid fixture");
    assert_eq!(
        fixture.mapping_revision,
        immortal_core::boltz_compat::BOLTZ_MAPPING_REVISION
    );
    assert_eq!(fixture.route_cases.len(), 19);
    assert_eq!(fixture.coverage.backend_v2_route_denominator, 53);
    assert_eq!(fixture.coverage.endpoint_surface_emulated_routes, 17);
    assert_eq!(fixture.coverage.dependent_call_route_denominator, 19);
    assert_eq!(fixture.coverage.dependent_call_emulated_routes, 19);
    assert!(fixture.coverage.relay_redirect_routes_are_not_emulation);
    for case in fixture.route_cases {
        assert!(
            !case.callers.is_empty(),
            "route has no released-profile caller: {} {}",
            case.method,
            case.path
        );
        let class = classify_boltz_handoff(&case.method, &case.path)
            .unwrap_or_else(|| panic!("route was not classified: {} {}", case.method, case.path));
        assert_eq!(class.as_str(), case.class, "{} {}", case.method, case.path);
    }
    for path in fixture.rejected_paths {
        assert!(
            !safe_origin_form(&path),
            "unsafe fixture path was accepted: {path}"
        );
    }
    for case in fixture.routes_outside_profile {
        assert_eq!(
            classify_boltz_handoff(&case.method, &case.path),
            None,
            "route outside profile was handed off: {} {}",
            case.method,
            case.path
        );
    }
}

#[test]
fn adapted_client_fixture_pins_routes_and_removes_stock_funding_paths() {
    let facade: Fixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/boltz-facade-v2.json"
    ))
    .expect("valid facade fixture");
    let adapters: AdapterFixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/boltz-client-adapters-v1.json"
    ))
    .expect("valid adapter fixture");

    assert_eq!(adapters.mapping_revision, facade.mapping_revision);
    assert!(adapters.source_pins == facade.source_pins);
    assert_eq!(
        adapters.funding_law.sequence,
        [
            "prepare_raw_funding_transaction_without_broadcast",
            "derive_exact_transaction_sha256_and_output_index",
            "finalize_submarine_and_verify_and_persist_bilateral_contracts_and_script_exit",
            "broadcast_the_same_prepared_transaction",
        ]
    );
    assert!(adapters.funding_law.requester_contract_required);
    assert!(adapters.funding_law.provider_contract_required);
    assert!(
        adapters
            .funding_law
            .contract_ids_are_finalize_callback_outputs
    );
    assert!(adapters.funding_law.exact_funding_binding_required);
    assert!(adapters.funding_law.persisted_script_path_exit_required);
    assert!(
        adapters
            .funding_law
            .restored_authorization_snapshot_sha256_required
    );
    assert!(!adapters.funding_law.cooperative_endpoints_allowed);
    assert!(!adapters.funding_law.one_shot_prepare_and_broadcast_allowed);
    assert_eq!(
        adapters.funding_law.maximum_raw_transaction_bytes,
        1_000_000
    );

    let facade_routes = facade
        .route_cases
        .iter()
        .map(|case| fixture_route_shape(&case.method, &case.path))
        .collect::<BTreeSet<_>>();
    let declared_union = adapters
        .released_union_route_shapes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let client_union = adapters
        .clients
        .go
        .route_shapes
        .iter()
        .chain(&adapters.clients.web.route_shapes)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(adapters.released_union_route_shapes.len(), 19);
    assert_eq!(declared_union.len(), 19);
    assert_eq!(facade_routes, declared_union);
    assert_eq!(client_union, declared_union);
    assert_eq!(adapters.clients.go.route_shapes.len(), 13);
    assert_eq!(adapters.clients.web.route_shapes.len(), 15);
    assert_eq!(
        adapters
            .clients
            .go
            .route_shapes
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        13
    );
    assert_eq!(
        adapters
            .clients
            .web
            .route_shapes
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        15
    );

    assert_eq!(
        adapters.clients.go.source,
        "adapters/boltz-client-go/adapter.go"
    );
    assert_eq!(
        adapters.clients.web.source,
        "adapters/boltz-web-app/adapter.mjs"
    );
    assert_forbidden_tokens_absent(
        include_str!("../../../adapters/boltz-client-go/adapter.go"),
        &adapters.clients.go.forbidden_source_tokens,
    );
    assert_forbidden_tokens_absent(
        include_str!("../../../adapters/boltz-web-app/adapter.mjs"),
        &adapters.clients.web.forbidden_source_tokens,
    );

    assert!(adapters.coverage.adapter_source_and_unit_gate);
    assert!(adapters.coverage.provider_listener_process_gate);
    assert!(!adapters.coverage.pinned_upstream_client_builds);
    assert!(adapters.coverage.fresh_client_engine_session_per_seam);
    assert_eq!(adapters.coverage.dependent_call_emulated_routes, 19);
    assert_eq!(adapters.coverage.dependent_call_route_denominator, 19);
}

fn assert_forbidden_tokens_absent(source: &str, forbidden_tokens: &[String]) {
    for token in forbidden_tokens {
        assert!(
            !source.contains(token),
            "adapter source contains forbidden stock path {token:?}"
        );
    }
}

fn fixture_route_shape(method: &str, path: &str) -> String {
    let shape = match path {
        "/v2/version"
        | "/v2/swap/submarine"
        | "/v2/swap/reverse"
        | "/v2/ws"
        | "/v2/chain/fees"
        | "/v2/chain/BTC/fee"
        | "/v2/chain/BTC/height"
        | "/v2/chain/BTC/transaction"
        | "/v2/nodes/stats" => path,
        _ if path.starts_with("/v2/swap/status?ids=") => "/v2/swap/status?ids=:id...",
        _ if path.starts_with("/v2/swap/submarine/") && path.ends_with("/finalize") => {
            "/v2/swap/submarine/:id/finalize"
        }
        _ if path.starts_with("/v2/swap/submarine/") && path.ends_with("/transaction") => {
            "/v2/swap/submarine/:id/transaction"
        }
        _ if path.starts_with("/v2/swap/reverse/") && path.ends_with("/transaction") => {
            "/v2/swap/reverse/:id/transaction"
        }
        _ if path.starts_with("/v2/swap/submarine/") && path.ends_with("/preimage") => {
            "/v2/swap/submarine/:id/preimage"
        }
        _ if path.starts_with("/v2/swap/reverse/") && path.ends_with("/bip21") => {
            "/v2/swap/reverse/:invoice/bip21"
        }
        _ if path.starts_with("/v2/chain/BTC/transaction/") => "/v2/chain/BTC/transaction/:txid",
        _ if path.starts_with("/v2/swap/") => "/v2/swap/:id",
        _ => panic!("unknown released-client fixture route: {method} {path}"),
    };
    format!("{method} {shape}")
}
