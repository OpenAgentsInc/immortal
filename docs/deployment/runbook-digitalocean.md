# Runbook: DigitalOcean

Two paths exist on DigitalOcean:

- **Path A — Droplet.** A plain Debian VM. This is the recommended path for
  Immortal. It is the Debian runbook with a different control panel.
- **Path B — App Platform + Managed Postgres.** The path *Zero To
  Production In Rust* ch. 5 uses for its web service. It can host Immortal,
  but read the honest notes first: one of them requires an owner decision.

## Path A: Droplet (recommended)

1. Create a Droplet: Debian stable image, the smallest size is enough to
   start (1 vCPU / 1 GB), enable backups if you want provider-level disk
   snapshots.
2. Add your SSH key during creation. Log in: `ssh root@<DROPLET_IP>`.
3. Point DNS `A` (and `AAAA`) for `relay.example.com` at the Droplet IP.
   DigitalOcean DNS or any registrar works.
4. Optionally create a DigitalOcean Cloud Firewall allowing inbound TCP
   22, 80, 443 only, and attach it to the Droplet (equivalent to the `ufw`
   step in the Debian runbook — use one or the other).
5. Follow [`runbook-debian-vps.md`](runbook-debian-vps.md) from step 1 to
   the end. Nothing DigitalOcean-specific remains: Postgres from apt on the
   same box, systemd unit, Caddy or nginx for TLS, `pg_dump` backups.

Provider notes:

- Droplet snapshots/backups complement, not replace, `pg_dump`: a snapshot
  of a running Postgres restores to a crash-consistent state, while a dump
  is a clean logical copy you can restore anywhere.
- If you later split the database onto a second Droplet, put both in one
  VPC and keep Postgres listening on the private interface only. That is
  still one Postgres — the architecture is unchanged.

## Path B: App Platform + Managed Postgres (the book's path)

The book (ZTP, ch. 5) deploys with a committed `spec.yaml`, Docker build,
health-check probe, environment-variable secrets, a managed dev Postgres,
and `DATABASE_URL` injected by the platform. The same shape for Immortal:

### Honest fit assessment — read before choosing this path

1. **WebSockets:** App Platform supports WebSocket upgrades through its
   load balancer, so the core relay protocol works. Expect the platform to
   recycle instances during deploys and maintenance; clients reconnect,
   which the Nostr protocol and Immortal's fail-closed design tolerate.
2. **Managed Postgres requires TLS.** DigitalOcean Managed Postgres
   enforces TLS (`sslmode=require`). Immortal's allowed dependency set
   provides `tokio-postgres` with **no TLS backend**, so the binary cannot
   connect to Managed Postgres today. Path B therefore needs
   `tokio-postgres-rustls`. **Owner approval granted 2026-08-03** (recorded
   in `AGENTS.md` rule 2): the crate may be added behind a feature flag
   when this path is implemented. Until that implementation lands, use
   Path A, where Postgres is local and plaintext-on-localhost is correct.
3. **No local disk, no sidecars** — fine: Immortal keeps all state in
   Postgres and needs nothing else. This is where the one-binary design
   pays off.
4. **Trusted sources** (below) are the platform's substitute for the
   private network you would build yourself; use them.
5. Managed Postgres includes automated backups and point-in-time recovery;
   the `pg_dump` cron from the Debian runbook becomes optional
   belt-and-braces (run it from your workstation if you want an off-provider
   copy).

### Steps

1. Install and authenticate `doctl`:

   ```sh
   doctl auth init
   ```

2. Commit a spec file (shape per the book's ch. 5 spec, adapted):

   ```yaml
   # spec.yaml
   name: immortal
   region: fra
   services:
     - name: relay
       dockerfile_path: Dockerfile
       source_dir: .
       github:
         repo: <YOUR_GITHUB_ORG>/immortal
         branch: main
         deploy_on_push: true
       health_check:
         http_path: /health
       http_port: 8080
       instance_count: 1
       instance_size_slug: basic-xxs
       envs:
         - key: PORT
           scope: RUN_TIME
           value: "8080"
         - key: IMMORTAL_BIND_ADDR
           scope: RUN_TIME
           value: "0.0.0.0"
         - key: IMMORTAL_RELAY_URL
           scope: RUN_TIME
           value: "wss://relay.example.com"
         - key: IMMORTAL_TRUST_PROXY
           scope: RUN_TIME
           value: "true"
         - key: IMMORTAL_LOG_LEVEL
           scope: RUN_TIME
           value: "info"
         - key: DATABASE_URL
           scope: RUN_TIME
           value: ${immortal-db.DATABASE_URL}
   databases:
     - name: immortal-db
       engine: PG
       version: "16"
   ```

   Notes:
   - `${immortal-db.DATABASE_URL}` is the book's pattern: the platform
     injects the managed database's connection string (TLS-bearing — see
     honest note 2) at run time; no credential is committed.
   - The Dockerfile is the one in
     [`runbook-google-cloud.md`](runbook-google-cloud.md) (multi-stage,
     static binary).
   - `instance_count: 1`. Multiple instances work architecturally
     (`LISTEN/NOTIFY` + `ingest_seq` exist for exactly that), but scale out
     deliberately, not by default.

3. Create the app:

   ```sh
   doctl apps create --spec spec.yaml
   doctl apps list
   ```

   Subsequent pushes to `main` deploy automatically (`deploy_on_push`), the
   platform builds the Dockerfile, probes `/health`, and does a rolling
   replacement — the book's zero-downtime flow.

4. Migrations are embedded in the release and recorded with content hashes.
   The first new process applies pending versions under a Postgres advisory
   lock before binding; concurrent processes wait and verify. Do not run the
   raw SQL files from a developer machine, because that bypasses the ledger
   and needlessly opens external database access. A split-role deployment
   instead runs the same embedded runner as an App Platform job using the
   migration-owner credential; see [`database.md`](database.md).

5. Lock down **trusted sources** on the managed database so only the App
   Platform app can reach it. This is the book's closing security step for
   the chapter and is not optional.

6. Domain: add `relay.example.com` in the app's settings (Networking →
   Domains), create the CNAME it asks for. App Platform terminates TLS for
   you — consistent with Immortal's TLS-at-the-proxy invariant; the
   platform's edge is the proxy.

7. Verify:

   ```sh
   curl -fsS -H 'Accept: application/nostr+json' https://relay.example.com/
   ```

   Then connect a client to `wss://relay.example.com`, publish, and read
   back.

### When to prefer which path

| Situation | Path |
| --- | --- |
| Default; full control; no dependency changes | A (Droplet) |
| No-ssh operations, platform-managed TLS/deploys accepted, TLS-to-Postgres crate approved by owner | B (App Platform) |
| Cheapest possible relay | A (everything on one small Droplet) |
