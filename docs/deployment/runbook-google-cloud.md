# Runbook: Google Cloud

Two paths:

- **Path A — Cloud Run + Cloud SQL.** The relay process is stateless (all
  state in Postgres; `LISTEN/NOTIFY` + `ingest_seq` make multiple relay
  processes safe), so it fits Cloud Run. Read the WebSocket notes; they
  matter.
- **Path B — GCE VM.** A Debian VM that mirrors the Debian runbook.
  Simplest mental model, fewest platform behaviors to learn.

Placeholders: `<PROJECT_ID>`, `<REGION>` (e.g. `us-central1`),
`relay.example.com`, `<YOUR_DB_PASSWORD>`.

```sh
gcloud config set project <PROJECT_ID>
```

## Path A: Cloud Run + Cloud SQL

### A.1 Dockerfile

Multi-stage, applying the book's Docker insights (ZTP, ch. 5): dependency
layer caching via the cargo-chef principle, minimal runtime image. cargo-chef
is a build tool, not a runtime dependency, so using it in the builder stage
does not touch the dependency allowlist. The runtime stage is static musl on
`scratch`: Immortal needs no TLS libraries (TLS terminates at the platform;
Cloud SQL is reached over a platform-provided Unix socket), no shell, no
assets.

```dockerfile
# ---- chef: cache the dependency build as its own layer ----
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef && rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Dependency layer: rebuilt only when Cargo.toml/Cargo.lock change.
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
 && strip target/x86_64-unknown-linux-musl/release/immortal

# ---- runtime: the binary and nothing else ----
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/immortal /immortal
# Cloud Run injects PORT; the binary honors it (see configuration.md).
ENV IMMORTAL_BIND_ADDR=0.0.0.0
ENTRYPOINT ["/immortal"]
```

If musl ever becomes a problem, the fallback runtime stage is
`gcr.io/distroless/cc-debian12` with a plain gnu-target build — still no
shell, still minimal.

Add a `.dockerignore` (the book's build-context insight):

```text
target/
.git/
docs/
```

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
  --storage-auto-increase \
  --no-assign-ip \
  --network=default
gcloud sql databases create immortal --instance=immortal-pg
gcloud sql users create immortal --instance=immortal-pg \
  --password='<YOUR_DB_PASSWORD>'
```

Least privilege: `immortal` is a plain role owning one database. Do not use
the `postgres` superuser in `DATABASE_URL`. Connect once as admin and
tighten ownership:

```sh
gcloud sql connect immortal-pg --user=postgres --database=immortal
# In psql:
ALTER DATABASE immortal OWNER TO immortal;
```

Connection choice (this is the important design note): Cloud Run mounts a
**Unix domain socket** at `/cloudsql/<PROJECT_ID>:<REGION>:immortal-pg` when
you pass `--add-cloudsql-instances`. The platform encrypts and authenticates
the hop for you. `tokio-postgres` speaks Unix sockets natively, so **no TLS
crate is needed** — the dependency allowlist survives intact. The
private-IP alternative also works inside a VPC connector without TLS, but
the socket path is simpler and is what this runbook uses. (A TLS-to-Postgres
crate would only become necessary for direct public-IP connections; that
path is not used here and would require owner sign-off per AGENTS.md
rule 2.)

`LISTEN/NOTIFY` works over Cloud SQL and over the socket; it is plain
protocol.

### A.4 Secret Manager for the database credential

The book's principle (ZTP, ch. 5): secrets are injected by the platform,
never committed. On Google Cloud the store is Secret Manager, and Cloud Run
injects secrets as environment variables at deploy time.

```sh
printf 'host=/cloudsql/<PROJECT_ID>:<REGION>:immortal-pg user=immortal password=<YOUR_DB_PASSWORD> dbname=immortal' \
  | gcloud secrets create immortal-database-url --data-file=-

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

### A.5 Apply migrations

Run them through the Cloud SQL Auth Proxy from your workstation or CI (the
proxy is a local development tool, not a deployed service):

```sh
cloud-sql-proxy <PROJECT_ID>:<REGION>:immortal-pg --port 5433 &
for f in migrations/*.sql; do
  psql "postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5433/immortal" \
    -v ON_ERROR_STOP=1 --single-transaction -f "$f"
done
kill %1
```

(Once the `immortal migrate` subcommand exists, a Cloud Run Job with the
same image and `--add-cloudsql-instances` is the cleaner CI path.)

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
  --use-http2=false
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
# Upgrade: push a new image tag, then
gcloud run deploy immortal --region=<REGION> \
  --image=<REGION>-docker.pkg.dev/<PROJECT_ID>/immortal/immortal:<NEW_VERSION>
# Cloud Run does a rolling replacement; old revision drains, new one takes over.

# Rollback: route traffic back to the previous revision
gcloud run revisions list --service=immortal --region=<REGION>
gcloud run services update-traffic immortal --region=<REGION> \
  --to-revisions=<OLD_REVISION>=100
```

Apply migrations (additive-first) before deploying the image that needs
them, exactly as in the Debian runbook.

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
     --image-family=debian-12 --image-project=debian-cloud \
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
   Caddy or nginx for TLS, `pg_dump` cron, symlink upgrade/rollback.

4. Optional provider extras: VM snapshots as belt-and-braces
   (`gcloud compute disks snapshot ...`), and Cloud Logging's agent if you
   want journald shipped off-host. Neither changes the deployment shape.

Path B is the same one-box relay as the canonical runbook; choose it when
you want Google's network but not Cloud Run's request model.
