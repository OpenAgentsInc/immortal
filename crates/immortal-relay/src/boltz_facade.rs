//! Activation contract for the external-provider Boltz compatibility handoff.

use sha2::{Digest, Sha256};

use crate::gateway::GatewayError;

pub const BOLTZ_FACADE_CONFORMANCE_ENV: &str = "IMMORTAL_BOLTZ_FACADE_CONFORMANCE_SHA256";
pub const BOLTZ_FACADE_PROVIDER_BASE_URL_ENV: &str = "IMMORTAL_BOLTZ_FACADE_PROVIDER_BASE_URL";

const CONFIGURATION_SCHEMA_V1: &str = concat!(
    "openagents.mkt-swp.boltz-facade.config.v1\n",
    "activation=exact_fixture_and_config_sha256\n",
    "provider=external_process\n",
    "provider_origin_must_differ_from_relay_origin=true\n",
    "handoff=http_307_preserve_method_and_body\n",
    "relay_reads_body=false\n",
    "relay_persists_session=false\n",
    "submarine_finalize=required_before_broadcast\n",
    "nip11_advertisement=never\n",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoltzFacadeConfig {
    pub conformance_sha256: String,
    pub provider_base_url: String,
}

impl BoltzFacadeConfig {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.conformance_sha256 != boltz_facade_conformance_sha256() {
            return Err(GatewayError::Config(format!(
                "{BOLTZ_FACADE_CONFORMANCE_ENV} does not match the compiled compatibility fixture and configuration digest"
            )));
        }
        validate_provider_base_url(&self.provider_base_url)
    }

    pub fn redirect_location(&self, path_and_query: &str) -> Result<String, GatewayError> {
        if !immortal_core::boltz_compat::safe_origin_form(path_and_query) {
            return Err(GatewayError::Config(
                "Boltz compatibility request target is not a safe origin-form path".to_owned(),
            ));
        }
        Ok(format!("{}{}", self.provider_base_url, path_and_query))
    }
}

pub fn boltz_facade_conformance_sha256() -> String {
    let mut digest = Sha256::new();
    digest.update(b"openagents.mkt-swp.boltz-facade.conformance.v1\0");
    digest.update(include_bytes!(
        "../../../tests/fixtures/nipmkt/boltz-facade-v2.json"
    ));
    digest.update(b"\0");
    digest.update(CONFIGURATION_SCHEMA_V1.as_bytes());
    lower_hex(&digest.finalize())
}

pub(crate) fn same_origin(left: &str, right: &str) -> bool {
    canonical_origin(left).is_some_and(|left| canonical_origin(right) == Some(left))
}

fn validate_provider_base_url(value: &str) -> Result<(), GatewayError> {
    if value.is_empty()
        || value.len() > 2_048
        || value.ends_with('/')
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid_base_url());
    }
    let (secure, authority) = if let Some(authority) = value.strip_prefix("https://") {
        (true, authority)
    } else if let Some(authority) = value.strip_prefix("http://") {
        (false, authority)
    } else {
        return Err(invalid_base_url());
    };
    if authority.is_empty() || authority.contains('/') {
        return Err(invalid_base_url());
    }
    let host = authority_host(authority).ok_or_else(invalid_base_url)?;
    if !valid_host(host) {
        return Err(invalid_base_url());
    }
    if !secure && !is_loopback_host(host) {
        return Err(GatewayError::Config(format!(
            "{BOLTZ_FACADE_PROVIDER_BASE_URL_ENV} permits plaintext HTTP only for loopback providers"
        )));
    }
    Ok(())
}

fn authority_host(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority.get(1..end)?;
        if host.is_empty() || host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        let suffix = authority.get(end + 1..)?;
        if !suffix.is_empty() && (!suffix.starts_with(':') || !valid_port(suffix.get(1..)?)) {
            return None;
        }
        return Some(host);
    }
    let mut parts = authority.split(':');
    let host = parts.next()?;
    if host.is_empty() {
        return None;
    }
    if let Some(port) = parts.next() {
        if parts.next().is_some() || !valid_port(port) {
            return None;
        }
    }
    Some(host)
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port > 0)
}

fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || (host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            }))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn canonical_origin(value: &str) -> Option<(bool, String, u16)> {
    let (secure, authority, default_port) = if let Some(authority) = value.strip_prefix("https://")
    {
        (true, authority, 443)
    } else if let Some(authority) = value.strip_prefix("http://") {
        (false, authority, 80)
    } else {
        return None;
    };
    let host = authority_host(authority)?;
    let port = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let suffix = authority.get(end + 1..)?;
        if suffix.is_empty() {
            default_port
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        }
    } else if let Some((_, port)) = authority.rsplit_once(':') {
        port.parse().ok()?
    } else {
        default_port
    };
    Some((secure, host.to_ascii_lowercase(), port))
}

fn invalid_base_url() -> GatewayError {
    GatewayError::Config(format!(
        "{BOLTZ_FACADE_PROVIDER_BASE_URL_ENV} must be a bounded HTTPS origin or loopback HTTP origin without userinfo, path, query, fragment, or trailing slash"
    ))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        BoltzFacadeConfig, boltz_facade_conformance_sha256, same_origin, validate_provider_base_url,
    };
    use crate::gateway::GatewayConfig;

    #[test]
    fn provider_origin_requires_https_or_loopback_http() {
        for valid in [
            "https://provider.example",
            "https://provider.example:8443",
            "http://127.0.0.1:9092",
            "http://[::1]:9092",
        ] {
            validate_provider_base_url(valid).expect(valid);
        }
        for invalid in [
            "http://provider.example",
            "https://user@provider.example",
            "https://provider.example/path",
            "https://provider.example/",
            "https://provider.example?x=1",
            "https://[]",
            "https://provider.example:0",
            "https://provider_example",
            "https://-provider.example",
            "https://provider-.example",
        ] {
            assert!(
                validate_provider_base_url(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn redirect_preserves_only_safe_origin_form_targets() {
        let config = BoltzFacadeConfig {
            conformance_sha256: boltz_facade_conformance_sha256(),
            provider_base_url: "https://provider.example".to_owned(),
        };
        assert_eq!(
            config.redirect_location("/v2/version?x=1").unwrap(),
            "https://provider.example/v2/version?x=1"
        );
        assert!(
            config
                .redirect_location("//wrong.example/v2/version")
                .is_err()
        );
    }

    #[test]
    fn activation_rejects_a_stale_conformance_digest() {
        let config = BoltzFacadeConfig {
            conformance_sha256: "0".repeat(64),
            provider_base_url: "https://provider.example".to_owned(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn provider_origin_cannot_redirect_back_to_the_relay() {
        let mut gateway = GatewayConfig::new(
            "postgres://fixture.invalid/immortal".to_owned(),
            "127.0.0.1:8080".parse().unwrap(),
        );
        gateway.relay_url = Some("wss://relay.example".to_owned());
        gateway.boltz_facade = Some(BoltzFacadeConfig {
            conformance_sha256: boltz_facade_conformance_sha256(),
            provider_base_url: "https://relay.example".to_owned(),
        });
        assert!(gateway.validate().is_err());
    }

    #[test]
    fn origin_identity_normalizes_default_ports_and_host_case() {
        assert!(same_origin(
            "https://RELAY.example",
            "https://relay.example:443"
        ));
        assert!(same_origin("http://127.0.0.1", "http://127.0.0.1:80"));
        assert!(same_origin("http://[::1]", "http://[::1]:80"));
        assert!(!same_origin(
            "https://relay.example:8443",
            "https://relay.example"
        ));
    }
}
