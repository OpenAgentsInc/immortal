//! M4 actual-process proof. Run only through `scripts/test-postgres.sh`
//! against its dedicated disposable database.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use immortal::{
    domain::{Event, MKT_QUOTE_KIND, MKT_STATUS_KIND, RelaySigner, Tag},
    market::{MarketSigner, WrapMaterial, wrap_mkt_record},
    mkt_swp_coordination::{coordination_conformance_sha256, parse_coordination_wrap},
    store::Store,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, NoTls};
use tokio_tungstenite::tungstenite::{Message, WebSocket, client};

const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn m4_two_process_gap_and_chaos_contract() {
    let Ok(database_url) = std::env::var("IMMORTAL_TEST_DATABASE_URL") else {
        eprintln!("skipped: run scripts/test-postgres.sh");
        return;
    };
    if std::env::var("IMMORTAL_TEST_ALLOW_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!("skipped: M4 process proof requires a disposable database guard");
        return;
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut relay_one = RelayProcess::spawn(&database_url);
    let mut relay_two = RelayProcess::spawn(&database_url);
    assert_coordination_nip11(relay_one.address);
    assert_coordination_nip11(relay_two.address);
    let (admin, connection) = runtime
        .block_on(tokio_postgres::connect(&database_url, NoTls))
        .unwrap();
    let driver = runtime.spawn(connection);

    let mut subscriber = connect_client(relay_two.address);
    send_json(&mut subscriber, json!(["REQ", "all", {"kinds": [1]}]));
    assert_eq!(read_json(&mut subscriber), json!(["EOSE", "all"]));

    let mut publisher = connect_client(relay_one.address);
    let first = signed_event(31, now(), "cross-process");
    publish(&mut publisher, &first);
    assert_event(&mut subscriber, &first);

    let missed = signed_event(32, now(), "notification intentionally omitted");
    let missed_seq = runtime.block_on(insert_without_notify(&admin, &missed));
    let trigger = signed_event(33, now(), "gap trigger");
    publish(&mut publisher, &trigger);
    let caught_up = read_json(&mut subscriber);
    assert_eq!(caught_up[0], "EVENT");
    assert_eq!(caught_up[2]["id"], missed.id);
    let delivered_trigger = read_json(&mut subscriber);
    assert_eq!(delivered_trigger[0], "EVENT");
    assert_eq!(delivered_trigger[2]["id"], trigger.id);
    assert!(missed_seq > 0);

    runtime.block_on(assert_mkt_swp_coordination_two_process_consistency(
        &admin,
        &database_url,
        &mut publisher,
        &mut connect_client(relay_two.address),
    ));

    drop(publisher);
    let killed = relay_one.kill_and_wait();
    assert!(
        !killed.success(),
        "kill-one proof must terminate one process"
    );

    let mut survivor_publisher = connect_client(relay_two.address);
    let survivor = signed_event(34, now(), "survivor remains current");
    publish(&mut survivor_publisher, &survivor);
    assert_event(&mut subscriber, &survivor);

    runtime.block_on(inject_unbounded_gap(&admin));
    match subscriber.read() {
        Ok(Message::Close(_))
        | Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
        | Err(tokio_tungstenite::tungstenite::Error::AlreadyClosed)
        | Err(tokio_tungstenite::tungstenite::Error::Protocol(_)) => {}
        other => panic!("relay did not fail closed on an unbounded gap: {other:?}"),
    }
    let failed = relay_two.wait_for_exit(EXIT_TIMEOUT);
    assert!(
        !failed.success(),
        "a process that cannot prove its notification gap must exit non-zero"
    );

    drop(survivor_publisher);
    drop(admin);
    runtime.block_on(driver).unwrap().unwrap();
}

fn assert_coordination_nip11(address: SocketAddr) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {address}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let document: Value = serde_json::from_str(body).unwrap();
    assert!(
        document["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(32))
    );
    assert!(
        document["supported_extensions"]
            .as_array()
            .unwrap()
            .contains(&json!("mkt-swp-coordination:1"))
    );
}

struct RelayProcess {
    child: Option<Child>,
    address: SocketAddr,
}

impl RelayProcess {
    fn spawn(database_url: &str) -> Self {
        let relay_secret = hex(&[9; 32]);
        let mut child = Command::new(env!("CARGO_BIN_EXE_immortal"))
            .env("DATABASE_URL", database_url)
            .env("IMMORTAL_BIND_ADDR", "127.0.0.1")
            .env("IMMORTAL_PORT", "0")
            .env("IMMORTAL_DB_CONNECTIONS", "2")
            .env("IMMORTAL_RATE_EVENTS_PER_MIN_IP", "10000")
            .env("IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY", "10000")
            .env("IMMORTAL_RATE_REQ_PER_MIN_IP", "10000")
            .env("IMMORTAL_MAX_CONNECTIONS_PER_IP", "100")
            .env("IMMORTAL_RELAY_URL", "ws://127.0.0.1")
            .env("IMMORTAL_RELAY_SECRET_KEY", relay_secret)
            .env(
                "IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256",
                coordination_conformance_sha256(),
            )
            .env_remove("PORT")
            .env_remove("IMMORTAL_AUTH_REQUIRED")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        assert!(
            !line.is_empty(),
            "relay exited before reporting its address"
        );
        let startup: Value = serde_json::from_str(&line).unwrap();
        let address = startup["address"].as_str().unwrap().parse().unwrap();
        Self {
            child: Some(child),
            address,
        }
    }

    fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap()
    }

    fn wait_for_exit(&mut self, duration: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + duration;
        let child = self.child.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                self.child = None;
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "relay did not exit before timeout"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn insert_without_notify(admin: &Client, event: &Event) -> i64 {
    let statement = admin
        .prepare(
            r#"
            INSERT INTO nostr_event (
                id, pubkey, created_at, kind, tags, content, sig,
                replacement_identifier, expires_at
            )
            VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, NULL, NULL)
            RETURNING ingest_seq
            "#,
        )
        .await
        .unwrap();
    let created_at = i64::try_from(event.created_at).unwrap();
    let kind = i32::from(event.kind);
    let tags = serde_json::to_string(&event.tags).unwrap();
    admin
        .query_one(
            &statement,
            &[
                &event.id,
                &event.pubkey,
                &created_at,
                &kind,
                &tags,
                &event.content,
                &event.sig,
            ],
        )
        .await
        .unwrap()
        .get(0)
}

async fn inject_unbounded_gap(admin: &Client) {
    let latest_statement = admin
        .prepare("SELECT COALESCE(MAX(ingest_seq), 0) FROM nostr_event")
        .await
        .unwrap();
    let latest: i64 = admin
        .query_one(&latest_statement, &[])
        .await
        .unwrap()
        .get(0);
    let payload = (latest + 10_000).to_string();
    let statement = admin
        .prepare("SELECT pg_notify('immortal_event', $1)")
        .await
        .unwrap();
    admin.query_one(&statement, &[&payload]).await.unwrap();
}

fn connect_client(address: SocketAddr) -> WebSocket<TcpStream> {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut websocket = client(format!("ws://{address}/"), stream).unwrap().0;
    let challenge = read_json(&mut websocket);
    assert_eq!(challenge[0], "AUTH");
    websocket
}

fn publish(websocket: &mut WebSocket<TcpStream>, event: &Event) {
    let response = publish_response(websocket, event);
    assert_eq!(response[0], "OK");
    assert_eq!(response[1], event.id);
    assert_eq!(response[2], true);
}

fn publish_response(websocket: &mut WebSocket<TcpStream>, event: &Event) -> Value {
    send_json(websocket, json!(["EVENT", event]));
    read_json(websocket)
}

fn assert_event(websocket: &mut WebSocket<TcpStream>, event: &Event) {
    let message = read_json(websocket);
    assert_eq!(message[0], "EVENT");
    assert_eq!(message[1], "all");
    assert_eq!(message[2]["id"], event.id);
}

fn send_json(websocket: &mut WebSocket<TcpStream>, value: Value) {
    websocket.send(Message::text(value.to_string())).unwrap();
}

fn read_json(websocket: &mut WebSocket<TcpStream>) -> Value {
    loop {
        match websocket.read().unwrap() {
            Message::Text(text) => return serde_json::from_str(text.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

fn signed_event(secret_byte: u8, created_at: u64, content: &str) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let mut event = Event {
        id: "0".repeat(64),
        pubkey: keypair.x_only_public_key().0.to_string(),
        created_at,
        kind: 1,
        tags: Vec::new(),
        content: content.to_owned(),
        sig: "0".repeat(128),
    };
    let id = event.computed_id_bytes().unwrap();
    event.id = event.computed_id().unwrap();
    event.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
    event
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn assert_mkt_swp_coordination_two_process_consistency(
    admin: &Client,
    database_url: &str,
    relay_one: &mut WebSocket<TcpStream>,
    relay_two: &mut WebSocket<TcpStream>,
) {
    let provider = MarketSigner::from_secret_bytes([41; 32]).unwrap();
    let requester = MarketSigner::from_secret_bytes([42; 32]).unwrap();
    let handler = RelaySigner::from_secret_hex(&hex(&[9; 32])).unwrap();
    let created_at = now();
    let expiration = created_at + 300;
    let session_id = "51".repeat(32);
    let rfq_event_id = "52".repeat(32);
    let asset_id = "swp:1:bip122:000000000019d6689c085ae165831e93:btc:chain";

    let first_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at,
        &session_id,
        &rfq_event_id,
        "53",
        "54",
        5,
        expiration,
        "shared-btc",
        asset_id,
        30,
        100,
        "6a",
    );
    let second_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 1,
        &session_id,
        &rfq_event_id,
        "55",
        "56",
        6,
        expiration,
        "shared-btc",
        asset_id,
        30,
        100,
        "6b",
    );
    let sequence_fork_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 2,
        &session_id,
        &rfq_event_id,
        "67",
        "68",
        4,
        expiration,
        "shared-btc",
        asset_id,
        10,
        100,
        "6c",
    );
    let overallocated_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 3,
        &session_id,
        &rfq_event_id,
        "69",
        "6b",
        7,
        expiration,
        "shared-btc",
        asset_id,
        50,
        100,
        "6d",
    );
    let capacity_increase_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 4,
        &session_id,
        &rfq_event_id,
        "6c",
        "6d",
        8,
        expiration,
        "shared-btc",
        asset_id,
        50,
        200,
        "6e",
    );
    let commitment_reuse_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 5,
        &session_id,
        &rfq_event_id,
        "6e",
        "6f",
        9,
        expiration,
        "shared-btc",
        asset_id,
        10,
        200,
        "6e",
    );
    let reservation_id_conflict_quote = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 6,
        &session_id,
        &rfq_event_id,
        "70",
        "54",
        10,
        expiration,
        "shared-btc",
        asset_id,
        10,
        200,
        "71",
    );
    let first_wrap = wrap_for_handler(&provider, &handler, &first_quote, 61, created_at);
    let second_wrap = wrap_for_handler(&provider, &handler, &second_quote, 62, created_at + 1);
    let sequence_fork_wrap = wrap_for_handler(
        &provider,
        &handler,
        &sequence_fork_quote,
        66,
        created_at + 2,
    );
    let overallocated_wrap = wrap_for_handler(
        &provider,
        &handler,
        &overallocated_quote,
        69,
        created_at + 3,
    );
    let capacity_increase_wrap = wrap_for_handler(
        &provider,
        &handler,
        &capacity_increase_quote,
        70,
        created_at + 4,
    );
    let commitment_reuse_wrap = wrap_for_handler(
        &provider,
        &handler,
        &commitment_reuse_quote,
        71,
        created_at + 5,
    );
    let reservation_id_conflict_wrap = wrap_for_handler(
        &provider,
        &handler,
        &reservation_id_conflict_quote,
        72,
        created_at + 6,
    );

    let accepted = publish_response(relay_one, &first_wrap);
    assert_eq!(accepted[2], true);
    assert_eq!(
        accepted[3],
        "mkt-swp-coordination: mkt_swp_reservation_active"
    );
    let second = publish_response(relay_two, &second_wrap);
    assert_eq!(second[2], true);
    assert_eq!(
        second[3],
        "mkt-swp-coordination: mkt_swp_reservation_active"
    );
    let fork = publish_response(relay_two, &sequence_fork_wrap);
    assert_eq!(fork[2], false);
    assert_eq!(fork[3], "restricted: swp_reservation_fork");
    let refused = publish_response(relay_two, &overallocated_wrap);
    assert_eq!(refused[2], false);
    assert_eq!(refused[3], "restricted: swp_reservation_overallocated");
    assert_eq!(
        publish_response(relay_one, &capacity_increase_wrap)[2],
        true
    );
    let commitment_reuse = publish_response(relay_two, &commitment_reuse_wrap);
    assert_eq!(commitment_reuse[2], false);
    assert_eq!(commitment_reuse[3], "restricted: swp_reservation_fork");
    let idempotency_conflict = publish_response(relay_two, &reservation_id_conflict_wrap);
    assert_eq!(idempotency_conflict[2], false);
    assert_eq!(
        idempotency_conflict[3],
        "restricted: swp_idempotency_conflict"
    );
    let replay = publish_response(relay_two, &first_wrap);
    assert_eq!(replay[2], true);
    assert_eq!(
        replay[3],
        "mkt-swp-coordination: mkt_swp_reservation_active"
    );

    let counts = admin
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE active), count(*) FILTER (WHERE decision = 'swp_reservation_overallocated'), count(*) FILTER (WHERE decision = 'swp_reservation_fork'), count(*) FILTER (WHERE decision = 'swp_idempotency_conflict') FROM mkt_swp_reservation_claim",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 7);
    assert_eq!(counts.get::<_, i64>(1), 3);
    assert_eq!(counts.get::<_, i64>(2), 1);
    assert_eq!(counts.get::<_, i64>(3), 2);
    assert_eq!(counts.get::<_, i64>(4), 1);

    let race_quote_one = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 7,
        &session_id,
        &rfq_event_id,
        "72",
        "73",
        0,
        expiration,
        "race-btc",
        asset_id,
        60,
        100,
        "74",
    );
    let race_quote_two = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 7,
        &session_id,
        &rfq_event_id,
        "75",
        "76",
        0,
        expiration,
        "race-btc",
        asset_id,
        60,
        100,
        "77",
    );
    let race_wrap_one = wrap_for_handler(&provider, &handler, &race_quote_one, 73, created_at + 7);
    let race_wrap_two = wrap_for_handler(&provider, &handler, &race_quote_two, 76, created_at + 7);
    let (race_one, race_two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| publish_response(relay_one, &race_wrap_one));
        let two = scope.spawn(|| publish_response(relay_two, &race_wrap_two));
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(
        [
            race_one[2].as_bool().unwrap(),
            race_two[2].as_bool().unwrap()
        ]
        .into_iter()
        .filter(|accepted| *accepted)
        .count(),
        1
    );
    let race_refusal = [&race_one, &race_two]
        .into_iter()
        .find(|response| response[2] == json!(false))
        .unwrap();
    assert_eq!(race_refusal[3], "restricted: swp_reservation_fork");
    let lightning_asset_id = "swp:1:bip122:000000000019d6689c085ae165831e93:btc:lightning";
    let cross_asset_sequence_reuse = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 8,
        &session_id,
        &rfq_event_id,
        "86",
        "87",
        0,
        expiration,
        "race-btc",
        lightning_asset_id,
        10,
        100,
        "88",
    );
    let cross_asset_wrap = wrap_for_handler(
        &provider,
        &handler,
        &cross_asset_sequence_reuse,
        86,
        created_at + 8,
    );
    let cross_asset_refusal = publish_response(relay_one, &cross_asset_wrap);
    assert_eq!(cross_asset_refusal[2], false);
    assert_eq!(cross_asset_refusal[3], "restricted: swp_reservation_fork");

    let reservation_id_race_one = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 8,
        &session_id,
        &rfq_event_id,
        "89",
        "8a",
        0,
        expiration,
        "id-race-a",
        asset_id,
        10,
        100,
        "8b",
    );
    let reservation_id_race_two = coordinated_quote(
        &provider,
        requester.pubkey(),
        created_at + 8,
        &session_id,
        &rfq_event_id,
        "8c",
        "8a",
        0,
        expiration,
        "id-race-b",
        asset_id,
        10,
        100,
        "8d",
    );
    let reservation_id_wrap_one = wrap_for_handler(
        &provider,
        &handler,
        &reservation_id_race_one,
        89,
        created_at + 8,
    );
    let reservation_id_wrap_two = wrap_for_handler(
        &provider,
        &handler,
        &reservation_id_race_two,
        92,
        created_at + 8,
    );
    let (reservation_id_one, reservation_id_two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| publish_response(relay_one, &reservation_id_wrap_one));
        let two = scope.spawn(|| publish_response(relay_two, &reservation_id_wrap_two));
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(
        [
            reservation_id_one[2].as_bool().unwrap(),
            reservation_id_two[2].as_bool().unwrap(),
        ]
        .into_iter()
        .filter(|accepted| *accepted)
        .count(),
        1
    );
    let reservation_id_refusal = [&reservation_id_one, &reservation_id_two]
        .into_iter()
        .find(|response| response[2] == json!(false))
        .unwrap();
    assert_eq!(
        reservation_id_refusal[3],
        "restricted: swp_idempotency_conflict"
    );
    let reservation_id = "8a".repeat(32);
    let reservation_id_rows = admin
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE active), count(*) FILTER (WHERE decision = 'swp_idempotency_conflict') FROM mkt_swp_reservation_claim WHERE provider_pubkey = $1 AND reservation_id = $2",
            &[&provider.pubkey(), &reservation_id],
        )
        .await
        .unwrap();
    assert_eq!(reservation_id_rows.get::<_, i64>(0), 2);
    assert_eq!(reservation_id_rows.get::<_, i64>(1), 1);
    assert_eq!(reservation_id_rows.get::<_, i64>(2), 1);

    let shared_funding_ref = format!("{}:0", "85".repeat(32));
    let covenant_quote_one = coordinated_covenant_quote(
        &provider,
        requester.pubkey(),
        created_at + 8,
        &session_id,
        &rfq_event_id,
        "78",
        "79",
        expiration,
        "covenant-a",
        asset_id,
        "proof-a",
        &shared_funding_ref,
    );
    let covenant_quote_two = coordinated_covenant_quote(
        &provider,
        requester.pubkey(),
        created_at + 8,
        &session_id,
        &rfq_event_id,
        "7a",
        "7b",
        expiration,
        "covenant-b",
        asset_id,
        "proof-b",
        &shared_funding_ref,
    );
    let covenant_wrap_one =
        wrap_for_handler(&provider, &handler, &covenant_quote_one, 79, created_at + 8);
    let covenant_wrap_two =
        wrap_for_handler(&provider, &handler, &covenant_quote_two, 81, created_at + 8);
    let (covenant_one, covenant_two) = std::thread::scope(|scope| {
        let one = scope.spawn(|| publish_response(relay_one, &covenant_wrap_one));
        let two = scope.spawn(|| publish_response(relay_two, &covenant_wrap_two));
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(
        [
            covenant_one[2].as_bool().unwrap(),
            covenant_two[2].as_bool().unwrap(),
        ]
        .into_iter()
        .filter(|accepted| *accepted)
        .count(),
        1
    );
    let covenant_refusal = [&covenant_one, &covenant_two]
        .into_iter()
        .find(|response| response[2] == json!(false))
        .unwrap();
    assert_eq!(
        covenant_refusal[3],
        "restricted: swp_covenant_reserve_invalid"
    );
    let active_covenant_units: i64 = admin
        .query_one(
            "SELECT count(DISTINCT reserve_unit_sha256) FROM mkt_swp_reservation_claim WHERE active AND proof_class = 'covenant_reserve'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active_covenant_units, 1);

    let order_event_id = "57".repeat(32);
    let status_zero = coordinated_status(
        &provider,
        requester.pubkey(),
        created_at + 2,
        &session_id,
        &order_event_id,
        0,
        None,
        "58",
    );
    let status_two = coordinated_status(
        &provider,
        requester.pubkey(),
        created_at + 3,
        &session_id,
        &order_event_id,
        2,
        Some("59"),
        "5a",
    );
    let status_two_fork = coordinated_status(
        &provider,
        requester.pubkey(),
        created_at + 4,
        &session_id,
        &order_event_id,
        2,
        Some("59"),
        "5b",
    );
    let status_zero_wrap = wrap_for_handler(&provider, &handler, &status_zero, 63, created_at + 2);
    let status_two_wrap = wrap_for_handler(&provider, &handler, &status_two, 64, created_at + 3);
    let status_fork_wrap =
        wrap_for_handler(&provider, &handler, &status_two_fork, 65, created_at + 4);
    assert_eq!(publish_response(relay_one, &status_zero_wrap)[2], true);
    let gap = publish_response(relay_two, &status_two_wrap);
    assert_eq!(gap[3], "mkt-swp-coordination: swp_status_gap");
    let fork = publish_response(relay_one, &status_fork_wrap);
    assert_eq!(fork[3], "mkt-swp-coordination: swp_status_fork");

    let verification: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-verification.json"
    ))
    .unwrap();
    let raw_transaction = verification["transaction"]["raw"].as_str().unwrap();
    let raw_bytes = decode_hex(raw_transaction);
    let observed_status = provider.sign(
        created_at + 5,
        MKT_STATUS_KIND,
        vec![
            Tag::new(vec!["d".into(), "6d".repeat(32)]),
            Tag::new(vec!["session".into(), session_id.clone()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester.pubkey().into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Status".into()]),
            Tag::new(vec![
                "e".into(),
                order_event_id.clone(),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["seq".into(), "3".into()]),
            Tag::new(vec![
                "e".into(),
                status_two.id.clone(),
                String::new(),
                "previous".into(),
            ]),
            Tag::new(vec!["state".into(), "funding_observed".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session_id,
            "mkt_swp": {
                "swp_state": "funding_observed",
                "public_evidence": [{
                    "class": "bitcoin_transaction",
                    "rung": "measured",
                    "rail": "bitcoin",
                    "reference": verification["transaction"]["txid"],
                    "artifact_sha256": hex(&Sha256::digest(&raw_bytes)),
                    "producer_pubkey": provider.pubkey(),
                    "verifier_pubkey": null,
                    "verifier_policy": null,
                    "observed_at": created_at + 5,
                    "view": "submitted transaction bytes; no finality claim",
                    "raw_transaction": raw_transaction
                }]
            }
        })
        .to_string(),
    );
    let observed_wrap = wrap_for_handler(&provider, &handler, &observed_status, 72, created_at + 5);
    assert_eq!(publish_response(relay_two, &observed_wrap)[2], true);
    let observation = admin
        .query_one(
            "SELECT e.content, e.tags::text, o.source_event_id FROM mkt_swp_evidence_observation o JOIN nostr_event e ON e.id = o.observation_event_id",
            &[],
        )
        .await
        .unwrap();
    let public_content = observation.get::<_, String>(0);
    let public_tags = observation.get::<_, String>(1);
    assert!(public_content.contains("observation_not_authority"));
    for private_value in [
        session_id.as_str(),
        order_event_id.as_str(),
        provider.pubkey(),
        raw_transaction,
        observed_status.id.as_str(),
    ] {
        assert!(!public_content.contains(private_value));
        assert!(!public_tags.contains(private_value));
    }
    assert_eq!(
        observation.get::<_, String>(2),
        observed_status.id,
        "the private ledger retains the source link"
    );

    let store_one = Store::connect_verified(database_url).await.unwrap();
    let store_two = Store::connect_verified(database_url).await.unwrap();
    let view_one = store_one
        .mkt_swp_status_view(&session_id, &order_event_id, provider.pubkey())
        .await
        .unwrap();
    let view_two = store_two
        .mkt_swp_status_view(&session_id, &order_event_id, provider.pubkey())
        .await
        .unwrap();
    assert_eq!(view_one, view_two);
    assert_eq!(view_one.gaps, vec![1]);
    assert_eq!(view_one.forks[&2].len(), 2);

    let first_input = parse_coordination_wrap(&first_wrap, &handler)
        .unwrap()
        .unwrap();
    let mut replay_store = Store::connect_verified(database_url).await.unwrap();
    let expired_before_sweep = replay_store
        .apply_mkt_swp_coordination(&first_input, expiration + 1, &handler)
        .await
        .unwrap();
    assert!(!expired_before_sweep.accepted);
    assert_eq!(expired_before_sweep.code, "swp_reservation_expired");
    let released_on_replay = admin
        .query_one(
            "SELECT active, release_reason FROM mkt_swp_reservation_claim WHERE quote_event_id = $1",
            &[&first_quote.id],
        )
        .await
        .unwrap();
    assert!(!released_on_replay.get::<_, bool>(0));
    assert_eq!(released_on_replay.get::<_, String>(1), "expired");

    let active_before_sweep: i64 = admin
        .query_one(
            "SELECT count(*) FROM mkt_swp_reservation_claim WHERE active",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let released_one = store_one
        .release_expired_mkt_swp_reservations(expiration + 1)
        .await
        .unwrap();
    let released_two = store_two
        .release_expired_mkt_swp_reservations(expiration + 1)
        .await
        .unwrap();
    assert_eq!(
        released_one + released_two,
        u64::try_from(active_before_sweep).unwrap()
    );
    let expired_replay = publish_response(relay_two, &first_wrap);
    assert_eq!(expired_replay[2], false);
    assert_eq!(expired_replay[3], "restricted: swp_reservation_expired");
    let active: i64 = admin
        .query_one(
            "SELECT count(*) FROM mkt_swp_reservation_claim WHERE active",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 0);
    let participant_actions: i64 = admin
        .query_one(
            "SELECT count(*) FROM nostr_event WHERE kind BETWEEN 39604 AND 39610",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(participant_actions, 0);
}

#[allow(clippy::too_many_arguments)]
fn coordinated_quote(
    provider: &MarketSigner,
    requester_pubkey: &str,
    created_at: u64,
    session_id: &str,
    rfq_event_id: &str,
    distinct_byte: &str,
    reservation_byte: &str,
    allocation_sequence: u64,
    expiration: u64,
    capacity_bucket_id: &str,
    asset_id: &str,
    reserved_amount: u64,
    handler_committed_capacity: u64,
    commitment_byte: &str,
) -> Event {
    provider.sign(
        created_at,
        MKT_QUOTE_KIND,
        vec![
            Tag::new(vec!["d".into(), distinct_byte.repeat(32)]),
            Tag::new(vec!["session".into(), session_id.into()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester_pubkey.into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Quote".into()]),
            Tag::new(vec![
                "e".into(),
                rfq_event_id.into(),
                String::new(),
                "rfq".into(),
            ]),
            Tag::new(vec!["expiration".into(), expiration.to_string()]),
            Tag::new(vec!["quote".into(), "firm".into()]),
            Tag::new(vec!["reservation".into(), "soft".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session_id,
            "mkt_swp": {
                "reservation_terms": {
                    "reservation_id": reservation_byte.repeat(32),
                    "capacity_bucket_id": capacity_bucket_id,
                    "reserved_asset_id": asset_id,
                    "reserved_amount": reserved_amount.to_string(),
                    "handler_committed_capacity": handler_committed_capacity.to_string(),
                    "reservation_expires_at": expiration,
                    "allocation_sequence": allocation_sequence.to_string(),
                    "proof_class": "provider_signed",
                    "proof_ref": format!("provider-claim-{allocation_sequence}"),
                    "capacity_commitment_sha256": commitment_byte.repeat(32)
                }
            }
        })
        .to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn coordinated_covenant_quote(
    provider: &MarketSigner,
    requester_pubkey: &str,
    created_at: u64,
    session_id: &str,
    rfq_event_id: &str,
    distinct_byte: &str,
    reservation_byte: &str,
    expiration: u64,
    capacity_bucket_id: &str,
    asset_id: &str,
    proof_ref: &str,
    funding_ref: &str,
) -> Event {
    provider.sign(
        created_at,
        MKT_QUOTE_KIND,
        vec![
            Tag::new(vec!["d".into(), distinct_byte.repeat(32)]),
            Tag::new(vec!["session".into(), session_id.into()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester_pubkey.into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Quote".into()]),
            Tag::new(vec![
                "e".into(),
                rfq_event_id.into(),
                String::new(),
                "rfq".into(),
            ]),
            Tag::new(vec!["expiration".into(), expiration.to_string()]),
            Tag::new(vec!["quote".into(), "firm".into()]),
            Tag::new(vec!["reservation".into(), "hard".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session_id,
            "mkt_swp": {
                "reservation_terms": {
                    "reservation_id": reservation_byte.repeat(32),
                    "capacity_bucket_id": capacity_bucket_id,
                    "reserved_asset_id": asset_id,
                    "reserved_amount": "50",
                    "handler_committed_capacity": "100",
                    "reservation_expires_at": expiration,
                    "allocation_sequence": "0",
                    "proof_class": "covenant_reserve",
                    "proof_ref": proof_ref,
                    "capacity_commitment_sha256": distinct_byte.repeat(32),
                    "covenant": {
                        "funding_ref": funding_ref,
                        "program_sha256": "81".repeat(32),
                        "eligible_fill_sha256": "82".repeat(32),
                        "minimum_output": "50",
                        "fee_rule_sha256": "83".repeat(32),
                        "expires_at": expiration,
                        "verifier_view_sha256": "84".repeat(32)
                    }
                }
            }
        })
        .to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn coordinated_status(
    author: &MarketSigner,
    counterparty_pubkey: &str,
    created_at: u64,
    session_id: &str,
    order_event_id: &str,
    sequence: u64,
    previous_byte: Option<&str>,
    distinct_byte: &str,
) -> Event {
    let mut tags = vec![
        Tag::new(vec!["d".into(), distinct_byte.repeat(32)]),
        Tag::new(vec!["session".into(), session_id.into()]),
        Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
        Tag::new(vec![
            "p".into(),
            counterparty_pubkey.into(),
            String::new(),
            "requester".into(),
        ]),
        Tag::new(vec!["alt".into(), "MKT-SWP Status".into()]),
        Tag::new(vec![
            "e".into(),
            order_event_id.into(),
            String::new(),
            "order".into(),
        ]),
        Tag::new(vec!["seq".into(), sequence.to_string()]),
        Tag::new(vec!["state".into(), "awaiting_input".into()]),
    ];
    if let Some(previous_byte) = previous_byte {
        tags.push(Tag::new(vec![
            "e".into(),
            previous_byte.repeat(32),
            String::new(),
            "previous".into(),
        ]));
    }
    author.sign(
        created_at,
        MKT_STATUS_KIND,
        tags,
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session_id,
            "mkt_swp": {"swp_state": "requester_verification_passed"}
        })
        .to_string(),
    )
}

fn wrap_for_handler(
    sender: &MarketSigner,
    handler: &RelaySigner,
    event: &Event,
    material_byte: u8,
    created_at: u64,
) -> Event {
    wrap_mkt_record(
        &serde_json::to_vec(event).unwrap(),
        sender,
        handler.pubkey(),
        WrapMaterial {
            seal_created_at: created_at.saturating_sub(2),
            wrap_created_at: created_at.saturating_sub(1),
            seal_nonce: [material_byte; 32],
            wrap_nonce: [material_byte.wrapping_add(1); 32],
            wrap_secret: [material_byte.wrapping_add(2); 32],
        },
    )
    .unwrap()
    .event
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid fixture hex"),
    }
}
