# Configuration Contract

Immortal reads its configuration from environment variables only. There are
no configuration files and no command-line configuration flags. This adapts
the layered-configuration design of *Zero To Production In Rust* ch. 5 to a
minimal-dependency binary: the "layers" are whatever sets the environment
(systemd `EnvironmentFile`, a container platform, a shell), and the binary
sees one flat, typed contract.

## Rules

1. **Fail fast.** The binary validates all variables at startup, before it
   binds a socket or opens a database connection. On any missing required
   variable or unparsable value, it prints one clear error line to stderr
   and exits with a non-zero status.
2. **No secrets in argv.** Secrets pass only through the environment (or
   through files the environment points to). Command-line arguments are
   visible to other local users via `ps`.
3. **No secrets in logs.** Database credentials and relay signing keys never
   appear in a log line, error message, or panic output.
4. **Typed values.** Sizes are bytes, times are seconds, counts are
   integers. A value like `IMMORTAL_MAX_FRAME_BYTES=abc` is a startup
   error, not a silent default.
5. **Safe defaults.** Every optional variable has a conservative default.
   A bare `DATABASE_URL=... immortal` start is private (localhost bind) and
   rate-limited.

## Variables

### Database (required — one of the two forms)

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | yes* | — | Postgres connection string, e.g. `postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal`. Unix-socket form is supported: `postgres://immortal@%2Fvar%2Frun%2Fpostgresql/immortal` or keyword form `host=/var/run/postgresql user=immortal dbname=immortal`. |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | yes* | libpq-style defaults | Standard Postgres variables, used only when `DATABASE_URL` is not set. |

\* Exactly one form must be provided. If both are set, `DATABASE_URL` wins.

Note on TLS to Postgres: the allowed dependency set gives `tokio-postgres`
without a TLS backend, so database connections are plaintext. This is
correct for the supported topologies: same host, private Unix socket, or a
private network the platform secures. A deployment that requires TLS to the
database (for example a managed Postgres that enforces `sslmode=require`)
uses the owner-approved `tokio-postgres-rustls` backend. That optional feature
is approved in `AGENTS.md` but is not in the dependency tree yet; it lands
only with a managed-Postgres deployment path and a live TLS proof. The
DigitalOcean runbook therefore supports its Droplet topology and marks App
Platform + Managed Postgres unsupported for the current binary.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_DB_CONNECTIONS` | no | `4` | Worker database connections (1–64). Two additional dedicated connections are used for `LISTEN/NOTIFY` and the expiration sweep. |

### Network

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_BIND_ADDR` | no | `127.0.0.1` | Listen address. Keep the default behind a same-host reverse proxy. Set `0.0.0.0` in containers. |
| `IMMORTAL_PORT` | no | `8080` | Listen port for WebSocket and NIP-11 HTTP (one port, one listener). |
| `PORT` | no | — | Platform-injected port (for example Cloud Run). When set, it overrides `IMMORTAL_PORT`. |
| `IMMORTAL_RELAY_URL` | for NIP-42 | — | Public URL of this relay, e.g. `wss://relay.example.com`. Used to validate the `relay` tag in NIP-42 AUTH events and to advertise NIP-42 support in NIP-11. |
| `IMMORTAL_AUTH_REQUIRED` | no | `false` | Require a valid per-connection NIP-42 authentication event before EVENT or REQ. `IMMORTAL_RELAY_URL` must be set when this is true. |

### Protocol expansion

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_EXPIRATION_SWEEP_SECONDS` | no | `60` | Interval for physical NIP-40 cleanup (1–86,400). Queries exclude expired events independently of the sweep. |
| `IMMORTAL_RELAY_SECRET_KEY` | for NIP-29 or MKT-SWP coordination | — | Relay's 32-byte secret as 64 lowercase hexadecimal characters. Enables relay-managed groups and signed group history/metadata; with the exact coordination digest it is also the handler recipient and public-observation signer. The derived public key becomes the NIP-11 relay pubkey; if `IMMORTAL_RELAY_PUBKEY` is also set, it must match. This is a relay key, never a participant or wallet key, and belongs only in the protected runtime environment. |
| `IMMORTAL_MANAGEMENT_PUBKEY` | for NIP-86 | — | Exact 32-byte owner public key as 64 lowercase hexadecimal characters. Enables the NIP-98-authenticated management endpoint. `IMMORTAL_RELAY_URL` is required so HTTP authorization can bind the public URL. |
| `IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256` | to enable MKT-SWP coordination | — | Exact compiled fixture/migration/configuration digest printed at `.mkt.mkt_swp.coordination.conformance_sha256` by `immortal contract`. A missing value keeps the handler disabled; a stale or different value fails startup. Requires relay URL and relay secret. |
| `IMMORTAL_MKT_SWP_COORDINATION_SWEEP_SECONDS` | no | `30` | Reservation-release sweep interval when coordination is active (1–3,600). The sweep releases reservation accounting only. |

### Media

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_MEDIA_ROOT` | to enable M7 | — | Writable persistent directory for content-addressed Blossom bytes. Enabling it requires `IMMORTAL_RELAY_URL`. The committed Debian environment uses `/var/lib/immortal/media`. |
| `IMMORTAL_MEDIA_CLOUD_BASE_URL` | no | — | Enables the mounted-cloud adapter. Bytes are still atomically written through `IMMORTAL_MEDIA_ROOT`; reads redirect beneath this base using the immutable storage key and SHA-256. The mount and public URL must obey `docs/protocol/media.md`. |
| `IMMORTAL_MEDIA_MAX_BLOB_BYTES` | no | `10485760` | Maximum upload body, 1,024–1,073,741,824 bytes. Enforced from `Content-Length` before streaming. |
| `IMMORTAL_MEDIA_MAX_BYTES_PER_PUBKEY` | no | `1073741824` | Maximum owned bytes per authenticated pubkey, at least the blob limit and at most 1 TiB. Shared blobs count toward each owner. |

Media is disabled when `IMMORTAL_MEDIA_ROOT` is absent. The filesystem is the
default backend. Container deployments must bind-mount it persistently; do not
enable it on an ephemeral container filesystem. Upload and delete use one-use
NIP-98 events, while content-addressed GET and HEAD are public. The exact M7
surface and the deliberate Blossom BUD-11 authentication difference are in
`docs/protocol/media.md`.

NIP-17/NIP-70 delivery and publication checks are enabled when
`IMMORTAL_RELAY_URL` creates per-connection NIP-42 state. NIP-45 COUNT,
NIP-50 search, and NIP-65 relay-list storage need no extra variable. The full
contract and deliberate NIP-29 subset are in
`docs/protocol/nip-expansion.md`.

The same authenticated-recipient configuration gates the nonnumeric
`nip-mkt`, `mkt-swp:1`, `nip-mkt-pfi:1`, `nip-mkt-mint:1`, and
`nip-mkt-p2p:1` NIP-11 extensions. The profile extensions identify only their
relay-observable grammar and storage contract; they do not configure a wallet,
credential verifier, rail adapter, escrow or hold-invoice service, bond
custody, solver or arbiter, guarantee, dispute authority, or custody
surface. The separate
`mkt-swp-coordination:1` extension appears only when the exact conformance
digest, relay URL, and relay signer activate the noncustodial handler described
in `docs/protocol/mkt-swp-coordination.md`.

The Block extension handlers need no additional service or database. NIP-AO
uses the dedicated observer rates below. NIP-IA and NIP-DV require
`IMMORTAL_RELAY_SECRET_KEY` because their derived state is relay-signed;
NIP-WP requires `IMMORTAL_MANAGEMENT_PUBKEY`. The current release does not
configure or advertise a NIP-PL push executor; its handler fails closed. This
is a deployment-state statement, not a scope decision: the full-lane roadmap
requires an in-binary executor and its configuration after fixtures and a
manual platform-transport acceptance proof. See `docs/protocol/block-nips.md`.

TLS terminates at the reverse proxy. The binary itself never speaks TLS and
has no certificate configuration.

### Limits (all enforced; fail closed)

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_MAX_FRAME_BYTES` | no | `131072` | Maximum WebSocket frame/message and gateway event size in bytes (1,024–16,777,216). Larger frames close the connection; larger publications are refused. The database admission policy has its own content bound. |
| `IMMORTAL_MAX_SUBSCRIPTIONS` | no | `32` | Maximum concurrent subscriptions per connection (1–1,024). Excess `REQ` is answered with `CLOSED`. |
| `IMMORTAL_MAX_FILTERS` | no | `16` | Maximum filters per `REQ` (1–256). |
| `IMMORTAL_MAX_LIMIT` | no | `1000` | Cap on any filter `limit` (1–100,000); also the default page size when a filter has no `limit`. |
| `IMMORTAL_MAX_QUERY_COST` | no | `100000` | Upper bound on estimated rows scanned per `REQ` (1–1,000,000,000); costlier queries are refused with `CLOSED`. |
| `IMMORTAL_RATE_EVENTS_PER_MIN_IP` | no | `120` | `EVENT` messages accepted per minute per client IP. |
| `IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY` | no | `60` | `EVENT` messages accepted per minute per author pubkey. |
| `IMMORTAL_RATE_GIFT_WRAPS_PER_MIN_RECIPIENT` | no | `60` | Kind-1059 gift wraps accepted per minute for each outer `p` recipient. This complements the generic IP and outer wrapper-pubkey limits; the relay cannot observe the encrypted logical sender. |
| `IMMORTAL_RATE_OBSERVER_PER_SEC_IP` | no | `200` | NIP-AO observer frames accepted per second per client IP. |
| `IMMORTAL_RATE_OBSERVER_PER_SEC_AGENT` | no | `100` | NIP-AO observer frames accepted per second for each agent, including owner-to-agent control traffic. |
| `IMMORTAL_RATE_REQ_PER_MIN_IP` | no | `120` | `REQ` messages per minute per client IP. |
| `IMMORTAL_RATE_MEDIA_PER_MIN_IP` | no | `30` | Combined media uploads and deletes per minute per client IP. |
| `IMMORTAL_RATE_MEDIA_PER_MIN_PUBKEY` | no | `15` | Combined media uploads and deletes per minute per authenticated pubkey. |
| `IMMORTAL_MAX_CONNECTIONS_PER_IP` | no | `20` | Concurrent WebSocket connections per client IP (1–4,096). |
| `IMMORTAL_SEND_QUEUE_CAPACITY` | no | `256` | Maximum queued outbound messages per connection (8–65,536). Historical result batches and per-subscription EOSE buffers are each capped below half this value so their handoff remains bounded. A slow connection that fills the queue is closed. |

When the relay runs behind a reverse proxy, the client IP is taken from the
proxy connection's `X-Forwarded-For` / `X-Real-IP` header **only when**
`IMMORTAL_TRUST_PROXY=true` (default `false`). Never enable it when the
binary is directly reachable.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_TRUST_PROXY` | no | `false` | Trust forwarded-IP headers from the (single) upstream proxy. |

### Operations

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_LOG_LEVEL` | no | `info` | One of `error`, `warn`, `info`, `debug`. Logs are single-line JSON on stdout. |
| `IMMORTAL_SHUTDOWN_GRACE_SECONDS` | no | `10` | On SIGTERM: stop accepting, drain in-flight admissions, close connections, exit within this bound. |

### NIP-11 identity (optional, advertised only)

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_RELAY_NAME` | no | `immortal` | NIP-11 `name`. |
| `IMMORTAL_RELAY_DESCRIPTION` | no | empty | NIP-11 `description`. |
| `IMMORTAL_RELAY_CONTACT` | no | empty | NIP-11 `contact`. |
| `IMMORTAL_RELAY_PUBKEY` | no | empty | NIP-11 `pubkey` (operator's public key — never a private key). |

## Example: minimal local start

```sh
DATABASE_URL="postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal" \
IMMORTAL_LOG_LEVEL=info \
./immortal
```

## Example: production environment file

`/etc/immortal/immortal.env`, owned `root:immortal`, mode `0640` (see the
Debian runbook):

```sh
DATABASE_URL=postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=8080
IMMORTAL_RELAY_URL=wss://relay.example.com
IMMORTAL_TRUST_PROXY=true
IMMORTAL_EXPIRATION_SWEEP_SECONDS=60
IMMORTAL_MEDIA_ROOT=/var/lib/immortal/media
IMMORTAL_MEDIA_MAX_BLOB_BYTES=10485760
IMMORTAL_MEDIA_MAX_BYTES_PER_PUBKEY=1073741824
IMMORTAL_LOG_LEVEL=info
```

To enable groups and management, add the relay secret and management public
key to the installed protected file; never add their real values to the
repository or shell history:

```sh
IMMORTAL_RELAY_SECRET_KEY=<64-lowercase-hex-secret>
IMMORTAL_MANAGEMENT_PUBKEY=<64-lowercase-hex-public-key>
```

## Status note

The M1–M7 executable relay implements this contract. If implementation must
diverge, change this file in the same commit.
