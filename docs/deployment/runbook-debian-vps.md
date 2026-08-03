# Runbook: Debian VPS (canonical single-box deployment)

This is the canonical Immortal deployment: Debian 13 (`trixie`), Postgres 17
from apt, one `immortal` binary under systemd, and Caddy or nginx terminating
public TLS. It applies to a physical server or any VPS provider. All durable
state stays in the one Postgres database.

The committed files under `deploy/` are the source of truth for service,
proxy, environment, and backup configuration. Do not maintain private copies
of the snippets in this document.

Replace these placeholders before enabling the service:

- `relay.example.com` — the relay's public DNS name;
- `<YOUR_DB_PASSWORD>` — a long random database password; and
- `<VERSION>` — the immutable release label installed on this server.

Prerequisites:

- a fresh Debian 13 amd64 or arm64 server with root or sudo access;
- DNS `A` and, if applicable, `AAAA` records pointing at the server; and
- either a release binary built for the server or a repository checkout from
  which to build it.

## 1. Base system

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y postgresql curl ca-certificates
```

If building on the server, install Debian's Rust 1.85 toolchain and compiler:

```sh
sudo apt-get install -y cargo build-essential
cargo build --locked --release
```

Allow only SSH, HTTP, and HTTPS at the provider firewall. If the provider has
no firewall, use `ufw`:

```sh
sudo apt-get install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

The relay binds `127.0.0.1:8080`; never expose that port publicly.

## 2. Postgres

Debian's packaged Postgres starts automatically and listens locally. Create a
plain login role and one database without putting the password in shell
history:

```sh
sudo -u postgres createuser --pwprompt immortal
sudo -u postgres createdb --owner=immortal immortal
```

Verify the credential:

```sh
psql 'postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal' \
  --command='SELECT 1;'
```

The `immortal` role is not a superuser and owns only its database. The first
relay start applies the embedded schema under an advisory lock and records its
hash; do not apply files under `migrations/` directly with `psql`.

## 3. Install the binary

Use an immutable release directory and one atomic `current` symlink:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin immortal
sudo install -d -o root -g root -m 0755 /opt/immortal/releases/<VERSION>
sudo install -o root -g root -m 0755 immortal \
  /opt/immortal/releases/<VERSION>/immortal
sudo ln -sfn /opt/immortal/releases/<VERSION> /opt/immortal/current
```

When building from this checkout, the source path is
`target/release/immortal` instead of `immortal`.

## 4. Configure the environment

Install the committed template, then replace its password, hostname, and any
operator-specific values with `sudoedit`:

```sh
sudo install -d -o root -g immortal -m 0750 /etc/immortal
sudo install -o root -g immortal -m 0640 deploy/immortal.env.example \
  /etc/immortal/immortal.env
sudoedit /etc/immortal/immortal.env
if sudo grep -q '<' /etc/immortal/immortal.env; then
  echo 'ERROR: unresolved placeholder remains' >&2
  false
fi
```

The database password lives only in this root-owned file. Never put it in the
unit, command line, repository, or logs. The complete environment contract is
in [`configuration.md`](configuration.md).

## 5. Install the hardened systemd unit

```sh
sudo install -o root -g root -m 0644 deploy/systemd/immortal.service \
  /etc/systemd/system/immortal.service
sudo systemd-analyze verify /etc/systemd/system/immortal.service
sudo systemctl daemon-reload
sudo systemctl enable --now immortal.service
```

Verify startup and inspect the sandbox:

```sh
systemctl status immortal.service --no-pager
curl -fsS http://127.0.0.1:8080/health
curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:8080/
sudo systemd-analyze security --no-pager immortal.service
journalctl -u immortal.service -n 20 --no-pager
```

The canonical unit permits only localhost networking and port 8080, denies
filesystem writes, removes capabilities, restricts namespaces and system
calls, and stops within 15 seconds. Change the socket restrictions only if
you also change the documented single-box topology.

## 6. Put a TLS reverse proxy in front

Pick one. Both templates preserve WebSocket upgrades and the client-address
headers used when `IMMORTAL_TRUST_PROXY=true`.

### Caddy (recommended)

```sh
sudo apt-get install -y caddy
sudo install -o root -g root -m 0644 deploy/caddy/Caddyfile \
  /etc/caddy/Caddyfile
sudoedit /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy.service
```

Caddy obtains and renews the public certificate automatically.

### nginx

```sh
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo install -o root -g root -m 0644 deploy/nginx/immortal.conf \
  /etc/nginx/sites-available/immortal
sudoedit /etc/nginx/sites-available/immortal
sudo ln -sfn /etc/nginx/sites-available/immortal \
  /etc/nginx/sites-enabled/immortal
sudo nginx -t
sudo systemctl reload nginx.service
sudo certbot --nginx -d relay.example.com --redirect
```

The 600-second proxy timeouts are inactivity timeouts; normal WebSocket ping
traffic keeps a connection open.

Verify from outside the server:

```sh
curl -fsS -H 'Accept: application/nostr+json' \
  https://relay.example.com/
```

Then connect a Nostr client to `wss://relay.example.com`, publish an event,
and query it back.

## 7. Install and prove nightly backups

The backup service creates a private, atomic custom-format `pg_dump` every
night, retains 14 days locally, and catches up after downtime. Install the
committed artifacts:

```sh
sudo install -d -o postgres -g postgres -m 0700 /var/backups/immortal
sudo install -o root -g root -m 0755 deploy/backup/immortal-backup \
  /usr/local/sbin/immortal-backup
sudo install -o root -g root -m 0644 \
  deploy/backup/immortal-backup.service \
  deploy/backup/immortal-backup.timer \
  /etc/systemd/system/
sudo systemd-analyze verify \
  /etc/systemd/system/immortal-backup.service \
  /etc/systemd/system/immortal-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now immortal-backup.timer
sudo systemctl start immortal-backup.service
sudo systemctl status immortal-backup.service --no-pager
sudo ls -l /var/backups/immortal/
```

Copy backups off the server on an operator-controlled schedule. A dump on the
same disk is a restore point, not a disaster-recovery backup.

Test the newest dump immediately:

```sh
sudo -u postgres createdb --owner=immortal immortal_restore_test
sudo -u postgres pg_restore --role=immortal \
  --dbname=immortal_restore_test \
  /var/backups/immortal/immortal-<TIMESTAMP>.dump
sudo -u postgres psql --dbname=immortal_restore_test \
  --command='SELECT count(*) FROM nostr_event;'
sudo -u postgres psql --dbname=immortal_restore_test \
  --command='SELECT version, name, sha256 FROM schema_migrations ORDER BY version;'
sudo -u postgres dropdb immortal_restore_test
```

### Recover the production database

Keep the failed database until the restored relay passes verification:

```sh
sudo systemctl stop immortal.service
sudo -u postgres psql --dbname=postgres \
  --command="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'immortal';"
sudo -u postgres psql --dbname=postgres \
  --command='ALTER DATABASE immortal RENAME TO immortal_failed;'
sudo -u postgres createdb --owner=immortal immortal
sudo -u postgres pg_restore --role=immortal --dbname=immortal \
  /var/backups/immortal/immortal-<TIMESTAMP>.dump
sudo systemctl start immortal.service
curl -fsS http://127.0.0.1:8080/health
journalctl -u immortal.service -n 30 --no-pager
```

After publish/query verification and owner approval, remove
`immortal_failed`. If verification fails, stop the service, remove the newly
restored `immortal` database, rename `immortal_failed` back to `immortal`, and
start the service.

For a tighter recovery-point objective, configure Postgres WAL archiving and
periodic base backups to operator-controlled off-host storage. That remains
one Postgres; it does not add a product service.

## 8. Upgrade

Take and verify a fresh backup before changing the binary:

```sh
sudo systemctl start immortal-backup.service
sudo systemctl status immortal-backup.service --no-pager
sudo -u postgres psql --dbname=immortal \
  --command='SELECT version, name FROM schema_migrations ORDER BY version;'
```

Stage the new release beside the current one, flip the symlink, restart, and
verify:

```sh
sudo install -d -o root -g root -m 0755 \
  /opt/immortal/releases/<NEW_VERSION>
sudo install -o root -g root -m 0755 immortal \
  /opt/immortal/releases/<NEW_VERSION>/immortal
sudo ln -sfn /opt/immortal/releases/<NEW_VERSION> /opt/immortal/current
sudo systemctl restart immortal.service
curl -fsS http://127.0.0.1:8080/health
journalctl -u immortal.service -n 30 --no-pager
```

On SIGTERM the relay stops accepting connections, drains in-flight admission
within `IMMORTAL_SHUTDOWN_GRACE_SECONDS`, and exits. It never sends `OK`
before commit.

## 9. Roll back

Read the release notes before relying on a binary-only rollback. An older
binary deliberately rejects an unknown migration version, so a release that
applied a new migration requires the pre-upgrade database restore as well as
the old binary.

If the failed release applied no migration, flip back directly:

```sh
sudo ln -sfn /opt/immortal/releases/<OLD_VERSION> /opt/immortal/current
sudo systemctl restart immortal.service
curl -fsS http://127.0.0.1:8080/health
```

If it applied a migration, follow **Recover the production database** with
the pre-upgrade dump while the old binary is selected. This fail-closed rule
prevents an old release from silently interpreting a schema it does not know.

## 10. Routine checks

- `systemctl is-active immortal.service immortal-backup.timer`
- `journalctl -u immortal.service --since=-1h -p warning --no-pager`
- `curl -fsS https://relay.example.com/health` from off-host
- `df -h /var/lib/postgresql /var/backups/immortal`
- `sudo -u postgres psql --dbname=immortal --command="SELECT pg_size_pretty(pg_database_size('immortal'));"`
- `systemctl list-timers immortal-backup.timer --no-pager`
- restore the newest off-host dump into a temporary database at least monthly

## 11. Reproduce the fresh-Debian acceptance

The guarded acceptance command starts a disposable Debian 13 container,
installs apt Postgres and Debian Rust, builds the release binary, serves
health and NIP-11, publishes and reads a pinned signed event, then creates and
restores a logical backup:

```sh
./scripts/run-debian-acceptance.sh
```

It uses a running Apple Container, Podman, or Docker runtime selected locally
and requires a wrapper-only disposable-container guard before the destructive
inner script runs. It does not use GitHub workflows or any GitHub-billed
service.

## Current platform references

- [Debian releases](https://www.debian.org/releases/)
- [Debian 13 release information](https://www.debian.org/releases/trixie/)
