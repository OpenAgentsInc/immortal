//! Live M3 gateway conformance. The suite is destructive and must run only
//! through `scripts/test-postgres.sh` against its disposable database.

use std::{
    io::ErrorKind,
    net::{SocketAddr, TcpStream as StdTcpStream},
    time::Duration,
};

use immortal::{
    domain::{Event, Tag},
    gateway::{Gateway, GatewayConfig},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::tungstenite::{Message, WebSocket, client};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m3_gateway_contract_against_postgres() {
    let Ok(database_url) = std::env::var("IMMORTAL_TEST_DATABASE_URL") else {
        eprintln!("skipped: run scripts/test-postgres.sh");
        return;
    };
    if std::env::var("IMMORTAL_TEST_ALLOW_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: live gateway suite requires a disposable database guard");
        return;
    }

    let gateway_one = Gateway::start(test_config(database_url.clone()))
        .await
        .unwrap();
    let address_one = gateway_one.local_addr();
    let stop_one = gateway_one.shutdown_handle();
    let server_one = tokio::spawn(gateway_one.run());

    let gateway_two = Gateway::start(test_config(database_url)).await.unwrap();
    let address_two = gateway_two.local_addr();
    let stop_two = gateway_two.shutdown_handle();
    let server_two = tokio::spawn(gateway_two.run());

    assert_nip11_http(address_one).await;
    tokio::task::spawn_blocking(move || websocket_contract(address_one, address_two))
        .await
        .unwrap();

    stop_one.shutdown();
    stop_two.shutdown();
    timeout(Duration::from_secs(5), server_one)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(5), server_two)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

fn test_config(database_url: String) -> GatewayConfig {
    let mut config = GatewayConfig::new(database_url, "127.0.0.1:0".parse().unwrap());
    config.relay_url = Some("ws://relay.test".to_owned());
    config.auth_required = true;
    config.db_connections = 2;
    config.shutdown_grace = Duration::from_secs(2);
    config.limits.max_frame_bytes = 131_072;
    config.limits.max_subscriptions = 8;
    config.limits.max_filters = 4;
    config.limits.max_limit = 10;
    config.limits.max_query_cost = 10_000;
    config.limits.events_per_minute_ip = 100;
    config.limits.events_per_minute_pubkey = 100;
    config.limits.req_per_minute_ip = 100;
    config.limits.max_connections_per_ip = 10;
    config.limits.send_queue_capacity = 64;
    config
}

async fn assert_nip11_http(address: SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            b"GET /nested/path HTTP/1.1\r\nHost: relay.test\r\nAccept: application/nostr+json\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Access-Control-Allow-Origin: *\r\n"));
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    let document: Value = serde_json::from_str(body).unwrap();
    assert_eq!(document["name"], "immortal");
    assert_eq!(document["limitation"]["auth_required"], true);
    assert!(
        document["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(42))
    );
}

fn websocket_contract(address_one: SocketAddr, address_two: SocketAddr) {
    let mut subscriber = connect_client(address_two);
    let subscriber_challenge = expect_auth_challenge(&mut subscriber);
    send_json(&mut subscriber, json!(["REQ", "sub", {}]));
    let closed = read_json(&mut subscriber);
    assert_eq!(closed[0], "CLOSED");
    assert!(closed[2].as_str().unwrap().starts_with("auth-required:"));
    authenticate(&mut subscriber, 20, &subscriber_challenge);
    send_json(&mut subscriber, json!(["REQ", "sub", {}]));
    assert_eq!(read_json(&mut subscriber), json!(["EOSE", "sub"]));

    let mut publisher = connect_client(address_one);
    let publisher_challenge = expect_auth_challenge(&mut publisher);
    let auth_event = authenticate(&mut publisher, 21, &publisher_challenge);

    send_json(&mut publisher, json!(["EVENT", auth_event]));
    let rejected_auth_publish = read_json(&mut publisher);
    assert_eq!(rejected_auth_publish[0], "OK");
    assert_eq!(rejected_auth_publish[2], false);

    let regular = signed_event(21, now(), 1, Vec::new(), "cross-process durable");
    send_json(&mut publisher, json!(["EVENT", regular]));
    let accepted = read_json(&mut publisher);
    assert_eq!(accepted[0], "OK");
    assert_eq!(accepted[2], true);
    let delivered = read_json(&mut subscriber);
    assert_eq!(delivered[0], "EVENT");
    assert_eq!(delivered[1], "sub");
    assert_eq!(delivered[2]["id"], regular.id);

    send_json(&mut publisher, json!(["EVENT", regular]));
    let duplicate = read_json(&mut publisher);
    assert_eq!(duplicate[2], true);
    assert!(duplicate[3].as_str().unwrap().starts_with("duplicate:"));
    assert_no_message(&mut subscriber);

    let ephemeral = signed_event(22, now(), 20_000, Vec::new(), &"e".repeat(12_000));
    send_json(&mut publisher, json!(["EVENT", ephemeral]));
    assert_eq!(read_json(&mut publisher)[2], true);
    let delivered = read_json(&mut subscriber);
    assert_eq!(delivered[0], "EVENT");
    assert_eq!(delivered[2]["id"], ephemeral.id);

    send_json(
        &mut subscriber,
        json!(["REQ", "ephemeral-history", {"ids": [ephemeral.id]}]),
    );
    assert_eq!(
        read_json(&mut subscriber),
        json!(["EOSE", "ephemeral-history"])
    );

    send_json(&mut subscriber, json!(["CLOSE", "sub"]));
    let after_close = signed_event(23, now(), 1, Vec::new(), "after close");
    send_json(&mut publisher, json!(["EVENT", after_close]));
    assert_eq!(read_json(&mut publisher)[2], true);
    assert_no_message(&mut subscriber);

    subscriber.close(None).unwrap();
    publisher.close(None).unwrap();
}

fn connect_client(address: SocketAddr) -> WebSocket<StdTcpStream> {
    let stream = StdTcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (websocket, _) = client(format!("ws://{address}/any/path"), stream).unwrap();
    websocket
}

fn expect_auth_challenge(websocket: &mut WebSocket<StdTcpStream>) -> String {
    let message = read_json(websocket);
    assert_eq!(message[0], "AUTH");
    message[1].as_str().unwrap().to_owned()
}

fn authenticate(websocket: &mut WebSocket<StdTcpStream>, secret: u8, challenge: &str) -> Event {
    let event = signed_event(
        secret,
        now(),
        22_242,
        vec![
            Tag::new(vec!["relay".into(), "ws://relay.test".into()]),
            Tag::new(vec!["challenge".into(), challenge.to_owned()]),
        ],
        "",
    );
    send_json(websocket, json!(["AUTH", event]));
    let response = read_json(websocket);
    assert_eq!(response[0], "OK");
    assert_eq!(response[2], true);
    event
}

fn send_json(websocket: &mut WebSocket<StdTcpStream>, value: Value) {
    websocket.send(Message::text(value.to_string())).unwrap();
}

fn read_json(websocket: &mut WebSocket<StdTcpStream>) -> Value {
    loop {
        match websocket.read().unwrap() {
            Message::Text(text) => return serde_json::from_str(text.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

fn assert_no_message(websocket: &mut WebSocket<StdTcpStream>) {
    websocket
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    match websocket.read() {
        Err(tokio_tungstenite::tungstenite::Error::Io(error))
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        other => panic!("expected no WebSocket message, got {other:?}"),
    }
    websocket
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
}

fn signed_event(
    secret_byte: u8,
    created_at: u64,
    kind: u16,
    tags: Vec<Tag>,
    content: &str,
) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let mut event = Event {
        id: "0".repeat(64),
        pubkey: keypair.x_only_public_key().0.to_string(),
        created_at,
        kind,
        tags,
        content: content.to_owned(),
        sig: "0".repeat(128),
    };
    let id = event.computed_id_bytes().unwrap();
    event.id = event.computed_id().unwrap();
    event.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
    event
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
