# Runbook: Google Cloud

Two paths:

- **Path A — Cloud Run + Cloud SQL.** With M7 media disabled, the relay
  process is stateless (`LISTEN/NOTIFY` + `ingest_seq` make multiple relay
  processes safe), so it fits Cloud Run. Read the WebSocket notes; they
  matter. Do not set `IMMORTAL_MEDIA_ROOT` on Cloud Run's ephemeral ordinary
  filesystem.
- **Path B — GCE VM.** A Debian VM that mirrors the Debian runbook.
  Simplest mental model, fewest platform behaviors to learn.

Placeholders: `<PROJECT_ID>`, `<REGION>` (e.g. `us-central1`),
`relay.example.com`, `<YOUR_DB_PASSWORD>`.

```sh
gcloud config set project <PROJECT_ID>
```

## Path A: Cloud Run + Cloud SQL

### A.1 Container image

Use the committed root [`Dockerfile`](../../Dockerfile) and
[`.dockerignore`](../../.dockerignore). The multi-stage build pins its Rust
builder, compiles with `--locked`, strips the release binary, and copies it
into Debian 13 slim under an unprivileged numeric user. The runtime starts one
process: `/usr/local/bin/immortal`.

The Debian runtime is intentional. It matches the canonical operating-system
target, avoids an unproved musl variant, and carries the CA store needed by a
future owner-approved Postgres-TLS build without changing the image shape.
No database client, shell command, migration tool, or sidecar starts with the
container.

This path deliberately leaves M7 disabled. The container image can serve
media only when an operator supplies a persistent writable mount satisfying
`docs/protocol/media.md`; the ordinary Cloud Run filesystem does not. Path B
uses the canonical filesystem deployment.

### A.2 Artifact Registry

```sh
gcloud services enable artifactregistry.googleapis.com run.googleapis.com \
  sqladmin.googleapis.com secretmanager.googleapis.com

gcloud artifacts repositories create immortal \
  --repository-format=docker --location=<REGION>

gcloud auth configure-docker <REGION>-docker.pkg.dev
docker build -t <REGION>-docker.pkg.dev/<PROJECT_ID>/immortal/immortal:<VERSION> .
docker push  <REGION>-docker.pkg.dev/<PROJECT_ID>/immortal/immortal:<VERSION>
```

(Or `gcloud builds submit --tag ...` to build remotely.)

### A.3 Cloud SQL for Postgres

```sh
gcloud sql instances create immortal-pg \
  --database-version=POSTGRES_16 \
  --region=<REGION> \
  --tier=db-g1-small \
  --storage-auto-increase
gcloud sql databases create immortal --instance=immortal-pg
```

Least privilege: `immortal` is a plain role owning one database. Do not use
the `postgres` administrator in `DATABASE_URL`. Connect once as admin, create
the login, set its password through `psql`'s non-echoing prompt, and transfer
ownership:

```sh
gcloud sql connect immortal-pg --user=postgres --database=immortal
# In psql:
CREATE ROLE immortal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password immortal
ALTER DATABASE immortal OWNER TO immortal;
```

Connection choice (this is the important design note): Cloud Run mounts a
**Unix domain socket** at `/cloudsql/<PROJECT_ID>:<REGION>:immortal-pg` when
you pass `--add-cloudsql-instances`. Cloud Run's Cloud SQL integration
encrypts and authorizes the connection; no database authorized-network entry
is needed. `tokio-postgres` speaks Unix sockets natively, so **no TLS crate is
needed**. Direct database-IP connections are not part of this runbook.

`LISTEN/NOTIFY` works over Cloud SQL and over the socket; it is plain
protocol.

### A.4 Secret Manager for the database credential

The book's principle (ZTP, ch. 5): secrets are injected by the platform,
never committed. On Google Cloud the store is Secret Manager, and Cloud Run
injects secrets as environment variables at deploy time.

Create `immortal-database-url` in Secret Manager using the Cloud console. Paste
this value, replacing the password inside the quoted field:

```text
host=/cloudsql/<PROJECT_ID>:<REGION>:immortal-pg user=immortal password='<YOUR_DB_PASSWORD>' dbname=immortal
```

Using the console avoids putting the credential in argv or shell history.
Then create the runtime identity and grants:

```sh

# Allow the runtime service account to read it:
gcloud iam service-accounts create immortal-run
gcloud secrets add-iam-policy-binding immortal-database-url \
  --member="serviceAccount:immortal-run@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:immortal-run@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/cloudsql.client"
```

To rotate the credential: add a new secret version and redeploy. Nothing is
baked into the image.

### A.5 Migration behavior

Migrations are embedded in the release, serialized by a Postgres advisory
lock, and recorded with content hashes. Do not apply the raw SQL files with
`psql`, because doing so bypasses that ledger. With the simple owner role, the
first process applies pending versions before binding. M5 uses the single
database-owner login because the binary does not expose a migration-only
command; see [`database.md`](database.md).

### A.6 Deploy to Cloud Run

```sh
gcloud run deploy immortal \
  --image=<REGION>-docker.pkg.dev/<PROJECT_ID>/immortal/immortal:<VERSION> \
  --region=<REGION> \
  --service-account=immortal-run@<PROJECT_ID>.iam.gserviceaccount.com \
  --add-cloudsql-instances=<PROJECT_ID>:<REGION>:immortal-pg \
  --set-secrets=DATABASE_URL=immortal-database-url:latest \
  --set-env-vars=IMMORTAL_RELAY_URL=wss://relay.example.com,IMMORTAL_TRUST_PROXY=true,IMMORTAL_LOG_LEVEL=info \
  --port=8080 \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=1 \
  --concurrency=250 \
  --timeout=3600 \
  --session-affinity \
  --cpu=1 --memory=512Mi \
  --no-use-http2
```

WebSocket notes — why each flag is set:

- **`--timeout=3600`** — Cloud Run treats a WebSocket as one long request;
  the request timeout (max 60 minutes) hard-closes the socket. Clients
  reconnect (safe in Nostr; Immortal is designed for it), but set the
  maximum so churn is hourly, not every 5 minutes.
- **`--min-instances=1`** — a scale-to-zero relay would cold-start on every
  first connection and drop all subscriptions whenever it idled out. A
  relay should hold long-lived subscriptions; keep one instance warm.
- **`--max-instances=1` initially** — multiple instances are
  architecturally fine (many relay processes, one Postgres, event fan-out
  via `LISTEN/NOTIFY`, catch-up via `ingest_seq`). Start at 1; raise the
  cap deliberately when connection counts demand it, and watch Cloud SQL
  connection limits when you do (each instance holds
  `IMMORTAL_DB_CONNECTIONS` + 1).
- **`--concurrency=250`** — each open WebSocket occupies one request slot
  for its lifetime. Concurrency is therefore "max sockets per instance,"
  not requests/second. Size it with memory in mind.
- **`--session-affinity`** — best effort only. It helps reconnecting
  clients land on the instance that is already warm, but Immortal must not
  depend on it: any instance can serve any client, because all state is in
  Postgres. Affinity is an optimization, never a correctness requirement.
- Cloud Run's edge terminates TLS (`wss://` outside, `ws://` to the
  container) — consistent with the TLS-at-the-proxy invariant.
- Health: point startup/liveness probes at `/health` (Cloud Run HTTP
  probes), so an instance that cannot become current is replaced instead of
  serving fail-closed disconnects:

  ```sh
  gcloud run services update immortal --region=<REGION> \
    --startup-probe=httpGet.path=/health,initialDelaySeconds=2,periodSeconds=2,failureThreshold=15 \
    --liveness-probe=httpGet.path=/health,periodSeconds=30
  ```

### A.7 Domain and verify

```sh
gcloud run domain-mappings create --service=immortal \
  --domain=relay.example.com --region=<REGION>
# Create the DNS records it prints, wait for the certificate, then:
curl -fsS -H 'Accept: application/nostr+json' https://relay.example.com/
```

Connect a client to `wss://relay.example.com`, publish, read back. Logs:
Cloud Logging ingests the JSON lines from stdout as structured entries —
the payoff of line-oriented JSON logging (see `insights.md`, Telemetry).

### A.8 Upgrade and rollback

```sh
# Before upgrade, create an on-demand database backup.
gcloud sql backups create --instance=immortal-pg

# Deploy the already-pushed new image tag.
gcloud run deploy immortal --region=<REGION> \
  --image=<REGION>-docker.pkg.dev/<PROJECT_ID>/immortal/immortal:<NEW_VERSION>
# Cloud Run does a rolling replacement; old revision drains, new one takes over.

# If no migration was applied, route traffic back to the previous revision.
gcloud run revisions list --service=immortal --region=<REGION>
gcloud run services update-traffic immortal --region=<REGION> \
  --to-revisions=<OLD_REVISION>=100
```

An older revision rejects a schema containing an unknown migration when it
starts. If the failed revision applied a migration, restore the pre-upgrade
Cloud SQL backup or use point-in-time recovery before routing to the old
revision. Release notes must state migration and rollback compatibility.

### A.9 Replace a nostr-effect revision without changing DNS

When nostr-effect and Immortal use the same Cloud SQL database and Cloud Run
service, keep the existing custom-domain mapping and DNS records. Deploying a
no-traffic Immortal revision and then changing Cloud Run revision traffic is
faster and more reversible than moving the hostname or certificate.

The legacy source table is `public.events`. Migration 6 creates only an
Immortal-owned import ledger; it does not alter or delete that source table.
Set `IMMORTAL_IMPORT_NOSTR_EFFECT=true` only for this migration. On startup,
Immortal drains the legacy table in bounded batches before it binds the
listener. It then checks for newly arrived legacy rows every ten seconds by
default. Every source event keeps its ID and signature and passes through the
normal admission transaction. A nonzero `rejected` count in the structured
`nostr-effect import sweep` log is a cutover blocker.

1. Create an on-demand Cloud SQL backup and record the current service,
   revision, image digest, domain mapping, and traffic allocation.
2. Deploy the candidate to the same service with `--no-traffic` and a tag.
   Reuse the existing Cloud SQL attachment, runtime service account, database
   secret, and relay-signing secret. Add these environment values:

   ```text
   IMMORTAL_IMPORT_NOSTR_EFFECT=true
   IMMORTAL_LEGACY_IMPORT_SWEEP_SECONDS=10
   IMMORTAL_RELAY_URL=wss://relay.example.com
   IMMORTAL_TRUST_PROXY=true
   ```

3. Test the tag URL: `/health`, NIP-11, WebSocket upgrade, authenticated
   publish/read, broad historical COUNT, and the remote load gate. Confirm the
   startup import reached an empty sweep with zero rejected events.
4. Route 100% to the Immortal revision in one traffic update. Do not edit DNS.
   Wait at least two import-sweep intervals, then compare the legacy source
   count, import-ledger count, and rejection count. Verify the custom hostname
   again, including a newly signed publish/read round trip.
5. Keep the nostr-effect revision deployed as the immediate rollback target.
   A rollback routes 100% traffic to that recorded revision. Because migration
   6 is additive, the old process can continue using `public.events`; events
   accepted only by Immortal after cutover are not copied backward, so decide
   whether to replay them before a prolonged rollback.

After the legacy revision has been quiescent for the retention window, deploy
a new Immortal revision with `IMMORTAL_IMPORT_NOSTR_EFFECT=false`. Retain the
source table and ledger until the owner separately approves their removal.

Backups: Cloud SQL automated backups + point-in-time recovery:

```sh
gcloud sql instances patch immortal-pg \
  --backup-start-time=03:30 --enable-point-in-time-recovery
```

An off-provider `pg_dump` through the proxy remains good practice.

## Path B: GCE VM (mirrors the Debian runbook)

1. Create the VM and allow web traffic:

   ```sh
   gcloud compute instances create immortal-1 \
     --zone=<REGION>-b \
     --machine-type=e2-small \
     --image-family=debian-13 --image-project=debian-cloud \
     --tags=https-server,http-server
   gcloud compute firewall-rules create allow-http --allow=tcp:80 --target-tags=http-server
   gcloud compute firewall-rules create allow-https --allow=tcp:443 --target-tags=https-server
   ```

2. Point DNS `A` for `relay.example.com` at the VM's external IP
   (`gcloud compute instances describe immortal-1 --zone=<REGION>-b
   --format='get(networkInterfaces[0].accessConfigs[0].natIP)'`).

3. SSH in (`gcloud compute ssh immortal-1 --zone=<REGION>-b`) and follow
   [`runbook-debian-vps.md`](runbook-debian-vps.md) end to end: apt
   Postgres on the same VM, versioned binary layout, hardened systemd unit,
   Caddy or nginx for TLS, the backup timer, and schema-aware
   symlink upgrade/rollback.

4. Optional provider extras: VM snapshots as belt-and-braces
   (`gcloud compute disks snapshot ...`), and Cloud Logging's agent if you
   want journald shipped off-host. Neither changes the deployment shape.

Path B is the same one-box relay as the canonical runbook; choose it when
you want Google's network but not Cloud Run's request model.

## Current platform references

- [Cloud Run WebSocket behavior](https://cloud.google.com/run/docs/triggering/websockets)
- [Cloud Run request timeouts](https://cloud.google.com/run/docs/configuring/request-timeout)
- [Cloud Run to Cloud SQL connections](https://cloud.google.com/sql/docs/postgres/connect-run)
- [Compute Engine Debian image families](https://cloud.google.com/compute/docs/images/os-details)
