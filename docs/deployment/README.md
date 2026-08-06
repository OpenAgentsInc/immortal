# Deployment Documentation

This folder tells you how to deploy Immortal products: one Rust binary and one
Postgres database per product. The relay sits behind a reverse proxy that
terminates TLS. The custody-bearing provider is a separate product with its
own database and connects to operator-owned Bitcoin Core and Core Lightning
nodes, plus an optional operator-owned Elements node for Liquid service.

The material adapts the production practices from *Zero To Production In
Rust* by Luca Palmieri (2024-09-03 edition) to Immortal's constraints. The
book builds a web service with a large crate stack (actix-web, sqlx, config,
secrecy, tracing, reqwest). Immortal permits only seven direct dependencies
(`tokio`, `tokio-tungstenite`, `tokio-postgres`, `secp256k1`, `sha2`,
`serde`, `serde_json`). Where the book recommends a crate outside that list,
these documents extract the principle and describe the minimal-dependency way
to honor it. Where a crate addition seems genuinely necessary, the document
says so explicitly and marks it as requiring owner sign-off per `AGENTS.md`
rule 2. Nothing in this folder adds a second running service: no broker, no
cache, no sync engine. Postgres does all the storage work.

## Files

| File | Content |
| --- | --- |
| [`insights.md`](insights.md) | The book's production insights by theme, each mapped onto Immortal. |
| [`configuration.md`](configuration.md) | Immortal's configuration contract: environment variables only, with fail-fast validation. |
| [`database.md`](database.md) | Postgres schema, transactional admission, migrations, the current single-owner role, and the future split-role boundary. |
| [`import-jsonl.md`](import-jsonl.md) | Ordered signed-event JSONL export, offline import, report reconciliation, idempotent replay, and failure recovery. |
| [`gateway.md`](gateway.md) | HTTP/WebSocket runtime, indexed subscriptions, race-free EOSE, fanout, limits, and shutdown. |
| [`../conformance/README.md`](../conformance/README.md) | Fixture, live-Postgres, multi-process chaos, and release-load proof coverage. |
| [`runbook-debian-vps.md`](runbook-debian-vps.md) | The canonical single-box deployment: Debian 13, apt Postgres, hardened systemd, Caddy or nginx, backups, restore, upgrade, and schema-aware rollback. |
| [`runbook-digitalocean.md`](runbook-digitalocean.md) | DigitalOcean: the supported Debian 13 Droplet path and the explicit managed-platform boundary. |
| [`runbook-google-cloud.md`](runbook-google-cloud.md) | Google Cloud: Cloud Run + Cloud SQL + Secret Manager + Artifact Registry, and a GCE VM alternative. |
| [`runbook-local-dev.md`](runbook-local-dev.md) | Disposable local Postgres and relay plus the two-actor wrapped NIP-MKT smoke. |
| [`runbook-relay-migration.md`](runbook-relay-migration.md) | Incumbent policy mapping, signed-event import boundary, read-only WebSocket shadow, response diffs, and cutover gates. |
| [`runbook-provider-debian.md`](runbook-provider-debian.md) | The funded `immortal-provider` v1 prerequisites, custody boundary, separate Postgres, Bitcoin/Lightning/optional Liquid rails, service, health, funding, backup, and upgrade procedure. |
| [`runbook-swap-network.md`](runbook-swap-network.md) | Two-relay/two-provider stand-up, bounded live shadow, immutable client route pins, cutover, drain, rollback, and claim boundaries. |
| [`swap-network-infrastructure.md`](swap-network-infrastructure.md) | Role-by-role infrastructure for the decentralized Boltz-replacement swap network: relay, liquidity provider, client, and the minimum honest network. |

## Reading order

1. Read the root `README.md` and `AGENTS.md` first. They are binding.
2. Read `configuration.md` to learn the environment variables.
3. Read `database.md` for schema migration and role choices.
4. Read `import-jsonl.md` when replacing a relay with an ordered signed-event export.
5. Read `gateway.md` for runtime and failure behavior.
6. Pick one runbook and follow its numbered steps.
7. Read `insights.md` when you want the reasoning behind a step.

## Invariants that apply to every runbook

- One binary and one Postgres database per product. The provider's declared
  bitcoind, Lightning, optional elementsd, and hold-plugin rail prerequisites remain separate
  operator-owned systems; they do not enter the relay product.
- TLS terminates at the reverse proxy (Caddy, nginx, or a cloud load
  balancer). The binary speaks plain HTTP/WebSocket on a private address.
- Prepared SQL statements only.
- The relay fails closed: it sends `OK` only after the database commit, and
  it closes connections when it cannot become current.
- Ephemeral events (kinds 20000–29999) are never stored.
- No secrets in this repository. Runbooks use placeholders such as
  `<YOUR_DB_PASSWORD>`.
- No GitHub workflows or GitHub-billed conformance. Run the committed local
  proof commands manually.

## Committed deployment assets

The canonical relay and provider templates live under `deploy/`: environment
files, hardened systemd units, Caddy and nginx configurations, and separate
database backup services/timers.
The root `Dockerfile` is the Cloud Run image definition. The Debian runbook
installs these files directly so executable configuration and documentation
cannot drift independently.
