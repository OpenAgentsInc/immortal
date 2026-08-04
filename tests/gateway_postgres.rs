//! Live M3 gateway conformance. The suite is destructive and must run only
//! through `scripts/test-postgres.sh` against its disposable database.

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream as StdTcpStream},
    time::Duration,
};

use immortal::{
    domain::{Event, RelaySigner, Tag},
    gateway::{Gateway, GatewayConfig},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::Digest;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_postgres::NoTls;
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

    let verification_database_url = database_url.clone();
    let gateway_two = Gateway::start(test_config(database_url)).await.unwrap();
    let address_two = gateway_two.local_addr();
    let stop_two = gateway_two.shutdown_handle();
    let server_two = tokio::spawn(gateway_two.run());

    assert_nip11_http(address_one).await;
    let expired_id = tokio::task::spawn_blocking(move || {
        websocket_contract(address_one, address_two);
        management_contract(address_one);
        expanded_protocol_contract(address_one, address_two)
    })
    .await
    .unwrap();
    assert_physically_expired(&verification_database_url, &expired_id).await;

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
    config.expiration_sweep = Duration::from_secs(1);
    config.relay_signer = Some(RelaySigner::from_secret_hex(&hex(&[90; 32])).unwrap());
    config.identity.pubkey = config
        .relay_signer
        .as_ref()
        .map(|signer| signer.pubkey().to_owned());
    config.management_pubkey = Some(pubkey(91));
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
    for nip in [17, 29, 45, 50, 65, 70, 86, 98] {
        assert!(
            document["supported_nips"]
                .as_array()
                .unwrap()
                .contains(&json!(nip)),
            "missing NIP-{nip}"
        );
    }
}

fn websocket_contract(address_one: SocketAddr, address_two: SocketAddr) {
    let mut subscriber = connect_client(address_two);
    let subscriber_challenge = expect_auth_challenge(&mut subscriber);
    send_json(&mut subscriber, json!(["REQ", "sub", {}]));
    let closed = read_json(&mut subscriber);
    assert_eq!(closed[0], "CLOSED");
    assert!(closed[2].as_str().unwrap().starts_with("auth-required:"));
    authenticate(&mut subscriber, 20, &subscriber_challenge);
    send_json(&mut subscriber, json!(["UNSUPPORTED"]));
    assert_eq!(read_json(&mut subscriber)[0], "NOTICE");
    send_json(
        &mut subscriber,
        json!(["REQ", "too-many", {}, {}, {}, {}, {}]),
    );
    assert_eq!(read_json(&mut subscriber)[0], "CLOSED");
    send_json(&mut subscriber, json!(["REQ", "sub", {}]));
    assert_eq!(read_json(&mut subscriber), json!(["EOSE", "sub"]));

    let mut publisher = connect_client(address_one);
    let publisher_challenge = expect_auth_challenge(&mut publisher);
    let auth_event = authenticate(&mut publisher, 21, &publisher_challenge);

    send_json(&mut publisher, json!(["EVENT", auth_event]));
    let rejected_auth_publish = read_json(&mut publisher);
    assert_eq!(rejected_auth_publish[0], "OK");
    assert_eq!(rejected_auth_publish[2], false);

    let mut invalid = signed_event(21, now(), 1, Vec::new(), "invalid signature");
    invalid.content.push('!');
    send_json(&mut publisher, json!(["EVENT", invalid]));
    let invalid_response = read_json(&mut publisher);
    assert_eq!(invalid_response[0], "OK");
    assert_eq!(invalid_response[2], false);

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

    subscription_limit_contract(address_two);
    oversized_frame_contract(address_two);

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

fn management_contract(address: SocketAddr) {
    let methods = rpc_request(address, "supportedmethods", json!([]));
    assert!(methods["error"].is_null());
    for method in ["banpubkey", "allowkind", "creategroup", "putgroupuser"] {
        assert!(
            methods["result"]
                .as_array()
                .unwrap()
                .contains(&json!(method))
        );
    }

    let created = rpc_request(
        address,
        "creategroup",
        json!([
            "fixture-group",
            "Fixture Group",
            "M6 live group",
            "",
            false,
            pubkey(30),
            [1]
        ]),
    );
    assert_eq!(created["result"], true);
    let duplicate = rpc_request(
        address,
        "creategroup",
        json!([
            "fixture-group",
            "Duplicate Fixture Group",
            "must not restart the relay",
            "",
            false,
            pubkey(30),
            [1]
        ]),
    );
    assert!(
        duplicate["error"]
            .as_str()
            .unwrap()
            .contains("already exists")
    );
    assert!(
        rpc_request(address, "supportedmethods", json!([]))["error"].is_null(),
        "a rejected management mutation leaves the process current"
    );

    let banned = rpc_request(address, "banpubkey", json!([pubkey(88), "fixture block"]));
    assert_eq!(banned["result"], true);
    let listed = rpc_request(address, "listbannedpubkeys", json!([]));
    assert!(
        listed["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["pubkey"] == pubkey(88) && entry["reason"] == "fixture block" })
    );
    assert_eq!(
        rpc_request(address, "unbanpubkey", json!([pubkey(88)]))["result"],
        true
    );
}

fn expanded_protocol_contract(address_one: SocketAddr, address_two: SocketAddr) -> String {
    protected_and_private_contract(address_one, address_two);
    search_and_count_contract(address_one, address_two);
    group_contract(address_one, address_two);
    expiration_contract(address_one, address_two)
}

fn protected_and_private_contract(address_one: SocketAddr, address_two: SocketAddr) {
    let mut publisher = connect_client(address_one);
    let publisher_challenge = expect_auth_challenge(&mut publisher);
    authenticate(&mut publisher, 21, &publisher_challenge);

    let protected = signed_event(21, now(), 1, vec![Tag::new(vec!["-".into()])], "protected");
    send_json(&mut publisher, json!(["EVENT", protected]));
    assert_eq!(read_json(&mut publisher)[2], true);

    let forwarded = signed_event(22, now(), 1, vec![Tag::new(vec!["-".into()])], "forwarded");
    send_json(&mut publisher, json!(["EVENT", forwarded]));
    let refusal = read_json(&mut publisher);
    assert_eq!(refusal[2], false);
    assert!(refusal[3].as_str().unwrap().starts_with("auth-required:"));

    let repost = signed_event(
        21,
        now(),
        6,
        Vec::new(),
        &serde_json::to_string(&protected).unwrap(),
    );
    send_json(&mut publisher, json!(["EVENT", repost]));
    assert_eq!(read_json(&mut publisher)[2], false);
    let generic_repost = signed_event(
        21,
        now(),
        16,
        Vec::new(),
        &serde_json::to_string(&protected).unwrap(),
    );
    send_json(&mut publisher, json!(["EVENT", generic_repost]));
    assert_eq!(read_json(&mut publisher)[2], false);

    let mut recipient = connect_client(address_two);
    let challenge = expect_auth_challenge(&mut recipient);
    authenticate(&mut recipient, 30, &challenge);
    send_json(&mut recipient, json!(["REQ", "dm", {"kinds": [1059]}]));
    assert_eq!(read_json(&mut recipient), json!(["EOSE", "dm"]));

    let mut outsider = connect_client(address_two);
    let challenge = expect_auth_challenge(&mut outsider);
    authenticate(&mut outsider, 31, &challenge);
    send_json(
        &mut outsider,
        json!(["REQ", "not-my-dm", {"kinds": [1059]}]),
    );
    assert_eq!(read_json(&mut outsider), json!(["EOSE", "not-my-dm"]));

    let wrap = signed_event(
        55,
        now(),
        1_059,
        vec![Tag::new(vec!["p".into(), pubkey(30)])],
        "encrypted gift wrap",
    );
    send_json(&mut publisher, json!(["EVENT", wrap]));
    assert_eq!(read_json(&mut publisher)[2], true);
    assert_eq!(read_json(&mut recipient)[2]["id"], wrap.id);
    assert_no_message(&mut outsider);

    recipient.close(None).unwrap();
    outsider.close(None).unwrap();
    publisher.close(None).unwrap();
}

fn search_and_count_contract(address_one: SocketAddr, address_two: SocketAddr) {
    let mut publisher = connect_client(address_one);
    let challenge = expect_auth_challenge(&mut publisher);
    authenticate(&mut publisher, 21, &challenge);
    let searchable = signed_event(21, now(), 1, Vec::new(), "violet protocol expansion marker");
    let unrelated = signed_event(21, now(), 1, Vec::new(), "ordinary unrelated text");
    for event in [&searchable, &unrelated] {
        send_json(&mut publisher, json!(["EVENT", event]));
        assert_eq!(read_json(&mut publisher)[2], true);
    }

    let mut reader = connect_client(address_two);
    let challenge = expect_auth_challenge(&mut reader);
    authenticate(&mut reader, 20, &challenge);
    send_json(
        &mut reader,
        json!(["REQ", "search", {"search": "violet expansion"}]),
    );
    let result = read_json(&mut reader);
    assert_eq!(result[0], "EVENT");
    assert_eq!(result[2]["id"], searchable.id);
    assert_eq!(read_json(&mut reader), json!(["EOSE", "search"]));

    send_json(
        &mut reader,
        json!(["COUNT", "count-search", {"search": "violet expansion"}]),
    );
    assert_eq!(
        read_json(&mut reader),
        json!(["COUNT", "count-search", {"count": 1}])
    );
    reader.close(None).unwrap();
    publisher.close(None).unwrap();
}

fn group_contract(address_one: SocketAddr, address_two: SocketAddr) {
    let mut metadata_reader = connect_client(address_two);
    let challenge = expect_auth_challenge(&mut metadata_reader);
    authenticate(&mut metadata_reader, 20, &challenge);
    send_json(
        &mut metadata_reader,
        json!(["REQ", "metadata", {
            "kinds": [39000, 39001, 39002, 39003, 39004, 39005],
            "#d": ["fixture-group"]
        }]),
    );
    let mut metadata_kinds = Vec::new();
    loop {
        let message = read_json(&mut metadata_reader);
        if message == json!(["EOSE", "metadata"]) {
            break;
        }
        let event: Event = serde_json::from_value(message[2].clone()).unwrap();
        event.validate_crypto().unwrap();
        assert_eq!(event.pubkey, pubkey(90));
        metadata_kinds.push(event.kind);
    }
    metadata_kinds.sort_unstable();
    assert_eq!(
        metadata_kinds,
        vec![39_000, 39_001, 39_002, 39_003, 39_004, 39_005]
    );
    metadata_reader.close(None).unwrap();

    let mut admin = connect_client(address_one);
    let challenge = expect_auth_challenge(&mut admin);
    authenticate(&mut admin, 30, &challenge);
    let group_message = signed_event(
        30,
        now(),
        1,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "member message",
    );
    let group_message_prefix = group_message.id[..8].to_owned();
    send_json(&mut admin, json!(["EVENT", group_message]));
    assert_eq!(read_json(&mut admin)[2], true);

    let mut member = connect_client(address_one);
    let challenge = expect_auth_challenge(&mut member);
    authenticate(&mut member, 31, &challenge);
    let refused = signed_event(
        31,
        now(),
        1,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "not a member",
    );
    send_json(&mut member, json!(["EVENT", refused]));
    assert_eq!(read_json(&mut member)[2], false);

    let put_user = signed_event(
        30,
        now(),
        9_000,
        vec![
            Tag::new(vec!["h".into(), "fixture-group".into()]),
            Tag::new(vec!["p".into(), pubkey(31)]),
        ],
        "",
    );
    send_json(&mut admin, json!(["EVENT", put_user]));
    assert_eq!(read_json(&mut admin)[2], true);
    let admitted = signed_event(
        31,
        now(),
        1,
        vec![
            Tag::new(vec!["h".into(), "fixture-group".into()]),
            Tag::new(vec!["previous".into(), group_message_prefix]),
        ],
        "now a member",
    );
    send_json(&mut member, json!(["EVENT", admitted]));
    assert_eq!(read_json(&mut member)[2], true);
    let unknown_previous = signed_event(
        31,
        now(),
        1,
        vec![
            Tag::new(vec!["h".into(), "fixture-group".into()]),
            Tag::new(vec!["previous".into(), "deadbeef".into()]),
        ],
        "unknown timeline",
    );
    send_json(&mut member, json!(["EVENT", unknown_previous]));
    assert_eq!(read_json(&mut member)[2], false);

    let mut joiner = connect_client(address_one);
    let challenge = expect_auth_challenge(&mut joiner);
    authenticate(&mut joiner, 32, &challenge);
    let join = signed_event(
        32,
        now(),
        9_021,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "",
    );
    send_json(&mut joiner, json!(["EVENT", join]));
    assert_eq!(read_json(&mut joiner)[2], true);
    let joined_message = signed_event(
        32,
        now(),
        1,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "joined",
    );
    send_json(&mut joiner, json!(["EVENT", joined_message]));
    assert_eq!(read_json(&mut joiner)[2], true);
    let leave = signed_event(
        32,
        now(),
        9_022,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "",
    );
    send_json(&mut joiner, json!(["EVENT", leave]));
    assert_eq!(read_json(&mut joiner)[2], true);
    let after_leave = signed_event(
        32,
        now(),
        1,
        vec![Tag::new(vec!["h".into(), "fixture-group".into()])],
        "after leave",
    );
    send_json(&mut joiner, json!(["EVENT", after_leave]));
    assert_eq!(read_json(&mut joiner)[2], false);

    send_json(
        &mut joiner,
        json!(["REQ", "relay-membership-history", {
            "authors": [pubkey(90)],
            "kinds": [9000, 9001],
            "#h": ["fixture-group"],
            "#p": [pubkey(32)]
        }]),
    );
    let mut accepted_requests = std::collections::HashSet::new();
    loop {
        let message = read_json(&mut joiner);
        if message == json!(["EOSE", "relay-membership-history"]) {
            break;
        }
        let event: Event = serde_json::from_value(message[2].clone()).unwrap();
        event.validate_crypto().unwrap();
        accepted_requests.extend(event.tag_values("e").map(str::to_owned));
    }
    assert_eq!(
        accepted_requests,
        std::collections::HashSet::from([join.id, leave.id])
    );

    admin.close(None).unwrap();
    member.close(None).unwrap();
    joiner.close(None).unwrap();
}

fn expiration_contract(address_one: SocketAddr, address_two: SocketAddr) -> String {
    let mut publisher = connect_client(address_one);
    let challenge = expect_auth_challenge(&mut publisher);
    authenticate(&mut publisher, 21, &challenge);
    let expires_at = now() + 2;
    let event = signed_event(
        21,
        now(),
        1,
        vec![Tag::new(vec!["expiration".into(), expires_at.to_string()])],
        "swept",
    );
    send_json(&mut publisher, json!(["EVENT", event]));
    assert_eq!(read_json(&mut publisher)[2], true);

    std::thread::sleep(Duration::from_secs(4));
    let mut reader = connect_client(address_two);
    let challenge = expect_auth_challenge(&mut reader);
    authenticate(&mut reader, 20, &challenge);
    send_json(&mut reader, json!(["REQ", "expired", {"ids": [event.id]}]));
    assert_eq!(read_json(&mut reader), json!(["EOSE", "expired"]));
    reader.close(None).unwrap();
    publisher.close(None).unwrap();
    event.id
}

async fn assert_physically_expired(database_url: &str, event_id: &str) {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let statement = client
        .prepare("SELECT count(*) FROM nostr_event WHERE id = $1")
        .await
        .unwrap();
    let count = client
        .query_one(&statement, &[&event_id])
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(count, 0, "NIP-40 sweeper must physically delete expiration");
    drop(client);
    driver.await.unwrap().unwrap();
}

fn rpc_request(address: SocketAddr, method: &str, params: Value) -> Value {
    let body = json!({ "method": method, "params": params }).to_string();
    let payload_hash = hex(&sha2::Sha256::digest(body.as_bytes()));
    let event = signed_event(
        91,
        now(),
        27_235,
        vec![
            Tag::new(vec!["u".into(), "http://relay.test/manage".into()]),
            Tag::new(vec!["method".into(), "POST".into()]),
            Tag::new(vec!["payload".into(), payload_hash]),
        ],
        "",
    );
    let authorization = base64(&serde_json::to_vec(&event).unwrap());
    let mut stream = StdTcpStream::connect(address).unwrap();
    write!(
        stream,
        "POST /manage HTTP/1.1\r\nHost: relay.test\r\nContent-Type: application/nostr+json+rpc\r\nAuthorization: Nostr {authorization}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

fn subscription_limit_contract(address: SocketAddr) {
    let mut websocket = connect_client(address);
    let challenge = expect_auth_challenge(&mut websocket);
    authenticate(&mut websocket, 24, &challenge);
    for sequence in 0..8 {
        let subscription_id = format!("limit-{sequence}");
        send_json(
            &mut websocket,
            json!(["REQ", subscription_id, {"ids": ["f".repeat(64)]}]),
        );
        assert_eq!(read_json(&mut websocket)[0], "EOSE");
    }
    send_json(
        &mut websocket,
        json!(["REQ", "limit-refused", {"ids": ["f".repeat(64)]}]),
    );
    let response = read_json(&mut websocket);
    assert_eq!(response[0], "CLOSED");
    assert!(response[2].as_str().unwrap().starts_with("restricted:"));
    websocket.close(None).unwrap();
}

fn oversized_frame_contract(address: SocketAddr) {
    let mut websocket = connect_client(address);
    expect_auth_challenge(&mut websocket);
    websocket.send(Message::text("x".repeat(131_073))).unwrap();
    match websocket.read() {
        Ok(Message::Close(_))
        | Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
        | Err(tokio_tungstenite::tungstenite::Error::Protocol(_)) => {}
        other => panic!("oversized frame did not close the connection: {other:?}"),
    }
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

fn pubkey(secret_byte: u8) -> String {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0
        .to_string()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from((first & 0x03) << 4 | second >> 4)],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                TABLE[usize::from((second & 0x0f) << 2 | third >> 6)],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(TABLE[usize::from(third & 0x3f)]));
        } else {
            output.push('=');
        }
    }
    output
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
