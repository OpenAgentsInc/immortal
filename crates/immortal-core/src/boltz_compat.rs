//! Transport-neutral classification for the bounded Boltz compatibility handoff.

pub const BOLTZ_MAPPING_REVISION: &str = "openagents.mkt-swp.boltz-released-client.v2";
pub const BOLTZ_SUBMARINE_FINALIZE_SUFFIX: &str = "/finalize";

const MAX_ORIGIN_FORM_BYTES: usize = 2_048;
const MAX_STATUS_IDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoltzHandoffClass {
    ProviderPublic,
    ProviderSession,
    ProviderSensitive,
    ProviderWebSocket,
    SubmarineFinalize,
}

impl BoltzHandoffClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderPublic => "provider_public",
            Self::ProviderSession => "provider_session",
            Self::ProviderSensitive => "provider_sensitive",
            Self::ProviderWebSocket => "provider_websocket",
            Self::SubmarineFinalize => "submarine_finalize",
        }
    }
}

pub fn classify_boltz_handoff(method: &str, path_and_query: &str) -> Option<BoltzHandoffClass> {
    if !safe_origin_form(path_and_query) {
        return None;
    }
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    if method == "GET" && path == "/v2/ws" {
        return Some(BoltzHandoffClass::ProviderWebSocket);
    }
    if path == "/v2/swap/status" {
        return (method == "GET" && valid_status_query(path_and_query))
            .then_some(BoltzHandoffClass::ProviderPublic);
    }
    if !path.starts_with("/v2/") {
        return None;
    }
    if path.starts_with("/v2/swap/submarine/") && path.ends_with(BOLTZ_SUBMARINE_FINALIZE_SUFFIX) {
        return (method == "POST" && submarine_finalize_id(path).is_some())
            .then_some(BoltzHandoffClass::SubmarineFinalize);
    }
    if sensitive_route(method, path) {
        return Some(BoltzHandoffClass::ProviderSensitive);
    }
    if public_route(method, path) {
        return Some(BoltzHandoffClass::ProviderPublic);
    }
    session_route(method, path).then_some(BoltzHandoffClass::ProviderSession)
}

pub fn is_boltz_namespace(path_and_query: &str) -> bool {
    safe_origin_form(path_and_query)
        && (path_and_query == "/v2" || path_and_query.starts_with("/v2/"))
}

pub fn safe_origin_form(path_and_query: &str) -> bool {
    if path_and_query.is_empty()
        || !path_and_query.starts_with('/')
        || path_and_query.starts_with("//")
        || path_and_query.contains('#')
        || path_and_query.contains('\\')
        || path_and_query.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    if path_and_query.len() > MAX_ORIGIN_FORM_BYTES && !valid_status_query(path_and_query) {
        return false;
    }
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    let lowered = path.to_ascii_lowercase();
    !path.split('/').any(|segment| segment == "..")
        && !lowered.split('/').any(|segment| segment == "%2e%2e")
        && !lowered.contains("%2f")
        && !lowered.contains("%5c")
}

fn submarine_finalize_id(path: &str) -> Option<&str> {
    let id = path
        .strip_prefix("/v2/swap/submarine/")?
        .strip_suffix(BOLTZ_SUBMARINE_FINALIZE_SUFFIX)?;
    valid_hex_id(id).then_some(id)
}

fn sensitive_route(method: &str, path: &str) -> bool {
    if method == "GET" {
        return session_action(path, "submarine", "preimage");
    }
    if method != "POST" {
        return false;
    }
    chain_broadcast_path(path)
}

fn public_route(method: &str, path: &str) -> bool {
    if method != "GET" {
        return false;
    }
    if matches!(
        path,
        "/v2/version"
            | "/v2/swap/submarine"
            | "/v2/swap/reverse"
            | "/v2/chain/fees"
            | "/v2/nodes/stats"
    ) {
        return true;
    }
    if path.strip_prefix("/v2/swap/").is_some_and(valid_hex_id)
        || session_action(path, "submarine", "transaction")
        || session_action(path, "submarine", "preimage")
        || session_action(path, "reverse", "transaction")
        || reverse_bip21_path(path)
    {
        return true;
    }
    chain_read_path(path)
}

fn session_route(method: &str, path: &str) -> bool {
    method == "POST" && matches!(path, "/v2/swap/submarine" | "/v2/swap/reverse")
}

fn session_action(path: &str, swap_type: &str, action: &str) -> bool {
    let Some(rest) = path.strip_prefix(&format!("/v2/swap/{swap_type}/")) else {
        return false;
    };
    let Some(id) = rest.strip_suffix(&format!("/{action}")) else {
        return false;
    };
    valid_hex_id(id)
}

#[cfg(feature = "mkt-swp-verify")]
fn reverse_bip21_path(path: &str) -> bool {
    let Some(invoice) = path
        .strip_prefix("/v2/swap/reverse/")
        .and_then(|rest| rest.strip_suffix("/bip21"))
    else {
        return false;
    };
    crate::mkt_swp_verify::parse_bolt11(invoice).is_ok()
}

#[cfg(not(feature = "mkt-swp-verify"))]
fn reverse_bip21_path(_path: &str) -> bool {
    false
}

fn valid_status_query(path_and_query: &str) -> bool {
    let Some(query) = path_and_query.strip_prefix("/v2/swap/status?") else {
        return false;
    };
    if query.is_empty() {
        return false;
    }
    let mut count = 0_usize;
    for parameter in query.split('&') {
        let Some(id) = parameter.strip_prefix("ids=") else {
            return false;
        };
        if !valid_hex_id(id) {
            return false;
        }
        count += 1;
        if count > MAX_STATUS_IDS {
            return false;
        }
    }
    count > 0
}

fn chain_read_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v2/chain/") else {
        return false;
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        [currency, "fee" | "height"] => bounded_segment(currency),
        [currency, "transaction", transaction_id] => {
            bounded_segment(currency) && bounded_segment(transaction_id)
        }
        _ => false,
    }
}

fn chain_broadcast_path(path: &str) -> bool {
    let Some(rest) = path
        .strip_prefix("/v2/chain/")
        .and_then(|rest| rest.strip_suffix("/transaction"))
    else {
        return false;
    };
    bounded_segment(rest)
}

fn bounded_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{BoltzHandoffClass, classify_boltz_handoff, safe_origin_form};

    #[cfg(feature = "mkt-swp-verify")]
    const BOLT11: &str = "lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0";

    #[test]
    fn finalize_requires_post_and_a_lower_hex_identifier() {
        let id = "a".repeat(64);
        let path = format!("/v2/swap/submarine/{id}/finalize");
        assert_eq!(
            classify_boltz_handoff("POST", &path),
            Some(BoltzHandoffClass::SubmarineFinalize)
        );
        assert_eq!(
            classify_boltz_handoff("GET", &path),
            None,
            "a GET must not silently become a funding-finalization request"
        );
    }

    #[test]
    fn origin_form_rejects_redirect_header_and_path_confusion() {
        for path in [
            "//provider.example/v2/version",
            "/v2/../health",
            "/v2/%2e%2e/health",
            "/v2/a%2fb",
            "/v2/version#fragment",
            "/v2/version\r\nLocation: https://wrong.example",
        ] {
            assert!(!safe_origin_form(path), "accepted unsafe path {path:?}");
        }
    }

    #[test]
    fn status_query_admits_exactly_sixty_four_lower_hex_ids() {
        let id = "a".repeat(64);
        let query = (0..64)
            .map(|_| format!("ids={id}"))
            .collect::<Vec<_>>()
            .join("&");
        let path = format!("/v2/swap/status?{query}");
        assert!(path.len() > 2_048);
        assert!(safe_origin_form(&path));
        assert_eq!(
            classify_boltz_handoff("GET", &path),
            Some(BoltzHandoffClass::ProviderPublic)
        );

        let over_limit = format!("{path}&ids={id}");
        assert!(!safe_origin_form(&over_limit));
        assert_eq!(classify_boltz_handoff("GET", &over_limit), None);
        assert_eq!(
            classify_boltz_handoff("GET", &format!("/v2/swap/status?id={id}")),
            None
        );
    }

    #[test]
    #[cfg(feature = "mkt-swp-verify")]
    fn bip21_handoff_accepts_a_verified_ordinary_bolt11_only() {
        assert!(BOLT11.len() > 128);
        let path = format!("/v2/swap/reverse/{BOLT11}/bip21");
        assert_eq!(
            classify_boltz_handoff("GET", &path),
            Some(BoltzHandoffClass::ProviderPublic)
        );
        assert_eq!(
            classify_boltz_handoff(
                "GET",
                &format!("/v2/swap/reverse/lnbc{}/bip21", "q".repeat(256))
            ),
            None
        );
    }

    #[test]
    fn larger_request_targets_remain_closed_outside_exact_status_queries() {
        let path = format!("/v2/version?padding={}", "a".repeat(2_048));
        assert!(!safe_origin_form(&path));
        assert_eq!(classify_boltz_handoff("GET", &path), None);
    }
}
