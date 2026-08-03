# Deployment Documentation

This folder tells you how to deploy Immortal: one Rust binary and one
Postgres database, behind a reverse proxy that terminates TLS.

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
| [`database.md`](database.md) | Postgres schema, transactional admission, migrations, and simple or split least-privilege roles. |
| [`gateway.md`](gateway.md) | HTTP/WebSocket runtime, indexed subscriptions, race-free EOSE, fanout, limits, and shutdown. |
| [`../conformance/README.md`](../conformance/README.md) | Fixture, live-Postgres, multi-process chaos, and release-load proof coverage. |
| [`runbook-debian-vps.md`](runbook-debian-vps.md) | The canonical single-box deployment: Debian stable, apt Postgres, systemd, Caddy or nginx, backups, upgrade and rollback. Works on any VPS (Hetzner, OVH, and others). |
| [`runbook-digitalocean.md`](runbook-digitalocean.md) | DigitalOcean: the Droplet path, and the App Platform + Managed Postgres path the book uses, with honest notes on fit. |
| [`runbook-google-cloud.md`](runbook-google-cloud.md) | Google Cloud: Cloud Run + Cloud SQL + Secret Manager + Artifact Registry, and a GCE VM alternative. |

## Reading order

1. Read the root `README.md` and `AGENTS.md` first. They are binding.
2. Read `configuration.md` to learn the environment variables.
3. Read `database.md` for schema migration and role choices.
4. Read `gateway.md` for runtime and failure behavior.
5. Pick one runbook and follow its numbered steps.
6. Read `insights.md` when you want the reasoning behind a step.

## Invariants that apply to every runbook

- One binary and one Postgres database. Nothing else runs.
- TLS terminates at the reverse proxy (Caddy, nginx, or a cloud load
  balancer). The binary speaks plain HTTP/WebSocket on a private address.
- Prepared SQL statements only.
- The relay fails closed: it sends `OK` only after the database commit, and
  it closes connections when it cannot become current.
- Ephemeral events (kinds 20000–29999) are never stored.
- No secrets in this repository. Runbooks use placeholders such as
  `<YOUR_DB_PASSWORD>`.
