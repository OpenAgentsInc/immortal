use std::net::IpAddr;

use tokio::net::TcpStream;

use crate::{
    boltz_compat::{BOLTZ_MAPPING_REVISION, classify_boltz_handoff, is_boltz_namespace},
    boltz_facade::BoltzFacadeConfig,
};

use super::{
    GatewayError,
    rate::RateLimiter,
    socket::{HttpHead, write_http_bytes},
};

pub fn is_boltz_request(head: &HttpHead) -> bool {
    is_boltz_namespace(&head.path)
}

pub async fn serve_boltz(
    mut stream: TcpStream,
    head: &HttpHead,
    config: &BoltzFacadeConfig,
    rate: &RateLimiter,
    ip: IpAddr,
) -> Result<(), GatewayError> {
    if head.method == "OPTIONS" {
        return write_http_bytes(&mut stream, 204, "No Content", "text/plain", &[], &[]).await;
    }
    let Some(class) = classify_boltz_handoff(&head.method, &head.path) else {
        return json_error(
            &mut stream,
            404,
            "Not Found",
            "boltz_route_not_in_released_profile",
        )
        .await;
    };
    if !rate.req_from_ip(ip) {
        return json_error(
            &mut stream,
            429,
            "Too Many Requests",
            "boltz_handoff_rate_exceeded",
        )
        .await;
    }
    let location = config.redirect_location(&head.path)?;
    let headers = [
        ("Location", location),
        (
            "X-Immortal-Boltz-Profile",
            BOLTZ_MAPPING_REVISION.to_owned(),
        ),
        ("X-Immortal-Boltz-Handoff", class.as_str().to_owned()),
        ("Cache-Control", "no-store".to_owned()),
    ];
    write_http_bytes(
        &mut stream,
        307,
        "Temporary Redirect",
        "application/json",
        b"{\"handoff\":\"external_provider\"}",
        &headers,
    )
    .await
}

async fn json_error(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    code: &str,
) -> Result<(), GatewayError> {
    let body = format!("{{\"error\":\"{code}\"}}");
    write_http_bytes(
        stream,
        status,
        reason,
        "application/json",
        body.as_bytes(),
        &[("Cache-Control", "no-store".to_owned())],
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::is_boltz_request;
    use super::serve_boltz;
    use crate::{
        boltz_facade::{BoltzFacadeConfig, boltz_facade_conformance_sha256},
        gateway::{GatewayLimits, rate::RateLimiter, socket::HttpHead},
    };
    use std::collections::HashMap;
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, TcpStream},
    };

    fn head(path: &str) -> HttpHead {
        HttpHead {
            method: "GET".to_owned(),
            path: path.to_owned(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn namespace_does_not_capture_relay_health_or_nip11() {
        assert!(is_boltz_request(&head("/v2/version")));
        assert!(is_boltz_request(&head(&format!(
            "/v2/swap/status?ids={}",
            "a".repeat(64)
        ))));
        assert!(!is_boltz_request(&head("/streamswapstatus?id=x")));
        assert!(!is_boltz_request(&head("/health")));
        assert!(!is_boltz_request(&head("/")));
    }

    #[tokio::test]
    async fn sensitive_post_is_redirected_without_reading_its_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        });
        let (stream, peer) = listener.accept().await.unwrap();
        let request = HttpHead {
            method: "POST".to_owned(),
            path: "/v2/chain/BTC/transaction".to_owned(),
            headers: HashMap::from([("content-length".to_owned(), "1048576".to_owned())]),
        };
        let config = BoltzFacadeConfig {
            conformance_sha256: boltz_facade_conformance_sha256(),
            provider_base_url: "http://127.0.0.1:9092".to_owned(),
        };
        serve_boltz(
            stream,
            &request,
            &config,
            &RateLimiter::new(GatewayLimits::default()),
            peer.ip(),
        )
        .await
        .unwrap();
        let response = client.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 307 Temporary Redirect\r\n"));
        assert!(response.contains("X-Immortal-Boltz-Handoff: provider_sensitive\r\n"));
    }
}
