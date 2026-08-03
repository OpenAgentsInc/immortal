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
3. **No secrets in logs.** The database credential never appears in any log
   line, error message, or panic output.
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
needs a TLS crate (`tokio-postgres-rustls` or `postgres-native-tls`) —
**requires owner sign-off per AGENTS.md rule 2**. See the DigitalOcean
runbook for the concrete case.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_DB_CONNECTIONS` | no | `4` | Worker database connections. One additional dedicated connection is used for `LISTEN/NOTIFY`. |

### Network

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_BIND_ADDR` | no | `127.0.0.1` | Listen address. Keep the default behind a same-host reverse proxy. Set `0.0.0.0` in containers. |
| `IMMORTAL_PORT` | no | `8080` | Listen port for WebSocket and NIP-11 HTTP (one port, one listener). |
| `PORT` | no | — | Platform-injected port (Cloud Run, App Platform). When set, it overrides `IMMORTAL_PORT`. |
| `IMMORTAL_RELAY_URL` | for NIP-42 | — | Public URL of this relay, e.g. `wss://relay.example.com`. Used to validate the `relay` tag in NIP-42 AUTH events and advertised in NIP-11. Required if NIP-42 is enabled; startup error if NIP-42 is on and this is unset. |

TLS terminates at the reverse proxy. The binary itself never speaks TLS and
has no certificate configuration.

### Limits (all enforced; fail closed)

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `IMMORTAL_MAX_FRAME_BYTES` | no | `131072` | Maximum WebSocket frame/message size in bytes. Larger frames close the connection. Also bounds maximum stored event size. |
| `IMMORTAL_MAX_SUBSCRIPTIONS` | no | `32` | Maximum concurrent subscriptions per connection. Excess `REQ` is answered with `CLOSED`. |
| `IMMORTAL_MAX_FILTERS` | no | `16` | Maximum filters per `REQ`. |
| `IMMORTAL_MAX_LIMIT` | no | `1000` | Cap on any filter `limit`; also the default page size when a filter has no `limit`. |
| `IMMORTAL_MAX_QUERY_COST` | no | `100000` | Upper bound on estimated rows scanned per `REQ`; costlier queries are refused with `CLOSED`. |
| `IMMORTAL_RATE_EVENTS_PER_MIN_IP` | no | `120` | `EVENT` messages accepted per minute per client IP. |
| `IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY` | no | `60` | `EVENT` messages accepted per minute per author pubkey. |
| `IMMORTAL_RATE_REQ_PER_MIN_IP` | no | `120` | `REQ` messages per minute per client IP. |
| `IMMORTAL_MAX_CONNECTIONS_PER_IP` | no | `20` | Concurrent WebSocket connections per client IP. |

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
IMMORTAL_LOG_LEVEL=info
```

## Status note

The relay is currently a skeleton. This document is the binding contract for
the configuration surface as the implementation lands. If the implementation
must diverge, change this file in the same commit.
