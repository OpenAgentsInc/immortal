use immortal_core::boltz_compat::{classify_boltz_handoff, safe_origin_form};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    mapping_revision: String,
    route_cases: Vec<RouteCase>,
    rejected_paths: Vec<String>,
    routes_outside_profile: Vec<OutsideProfile>,
}

#[derive(Deserialize)]
struct RouteCase {
    method: String,
    path: String,
    class: String,
}

#[derive(Deserialize)]
struct OutsideProfile {
    method: String,
    path: String,
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
    for case in fixture.route_cases {
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
