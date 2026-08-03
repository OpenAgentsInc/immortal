# Runbook: Debian VPS (canonical single-box deployment)

This is the canonical Immortal deployment: one fresh Debian stable server,
Postgres from apt, the `immortal` binary under systemd, and Caddy or nginx
terminating TLS. It applies to any VPS provider (Hetzner, OVH, DigitalOcean
Droplet, a home server). Target time: minutes.

Placeholders to replace throughout: `relay.example.com` (your domain),
`<YOUR_DB_PASSWORD>` (a long random password), `<VERSION>` (the release you
deploy).

Prerequisites:

- A Debian stable (12+) server with root or sudo access.
- A DNS `A`/`AAAA` record for `relay.example.com` pointing at the server.
- The `immortal` release binary for `x86_64-unknown-linux-gnu` (build with
  `cargo build --release` on a matching Debian, or use the static musl
  build from the Docker runbook).

## 1. Base system

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y postgresql curl ca-certificates
```

Optional but recommended firewall (allow SSH, HTTP, HTTPS only):

```sh
sudo apt-get install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

The relay itself binds `127.0.0.1` and is never exposed directly.

## 2. Postgres

Debian's packaged Postgres starts automatically and listens on localhost
only, which is what we want.

```sh
sudo -u postgres psql -c "CREATE ROLE immortal LOGIN PASSWORD '<YOUR_DB_PASSWORD>';"
sudo -u postgres psql -c "CREATE DATABASE immortal OWNER immortal;"
```

Verify:

```sh
psql "postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal" -c "SELECT 1;"
```

Least privilege: the `immortal` role owns only its database and is not a
superuser. Do not grant more.

## 3. Install the binary and migrations

Use a versioned layout so rollback is a symlink flip:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin immortal
sudo mkdir -p /opt/immortal/releases/<VERSION>
sudo cp immortal /opt/immortal/releases/<VERSION>/immortal
sudo cp -r migrations /opt/immortal/releases/<VERSION>/migrations
sudo chmod 755 /opt/immortal/releases/<VERSION>/immortal
sudo ln -sfn /opt/immortal/releases/<VERSION> /opt/immortal/current
```

Apply migrations (in order, each in one transaction; the relay also verifies
schema version at startup and refuses to run against a schema it does not
understand):

```sh
cd /opt/immortal/current
for f in migrations/*.sql; do
  psql "postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal" \
    -v ON_ERROR_STOP=1 --single-transaction -f "$f"
done
```

(When the `immortal migrate` subcommand lands, prefer it: it records applied
versions with content hashes and skips already-applied files.)

## 4. Environment file

```sh
sudo mkdir -p /etc/immortal
sudo tee /etc/immortal/immortal.env >/dev/null <<'EOF'
DATABASE_URL=postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=8080
IMMORTAL_RELAY_URL=wss://relay.example.com
IMMORTAL_TRUST_PROXY=true
IMMORTAL_LOG_LEVEL=info
EOF
sudo chown root:immortal /etc/immortal/immortal.env
sudo chmod 0640 /etc/immortal/immortal.env
```

Secrets live only in this root-owned file — never in the unit file, never in
argv. See `configuration.md` for every variable and default.

## 5. systemd unit (with hardening)

```sh
sudo tee /etc/systemd/system/immortal.service >/dev/null <<'EOF'
[Unit]
Description=Immortal Nostr relay
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=immortal
Group=immortal
EnvironmentFile=/etc/immortal/immortal.env
ExecStart=/opt/immortal/current/immortal
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536

# Hardening: the relay needs the network, read access to its binary,
# and nothing else. Fail closed at the sandbox level too.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now immortal
```

Verify:

```sh
systemctl status immortal --no-pager
curl -fsS http://127.0.0.1:8080/health
curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:8080/
journalctl -u immortal -n 20 --no-pager
```

Logs are single-line JSON on stdout; journald captures them. Query with
`journalctl -u immortal -o cat | tail`.

## 6. Reverse proxy with TLS

TLS always terminates here, not in the binary. Pick Caddy (simplest,
automatic certificates) or nginx.

### Option A: Caddy

```sh
sudo apt-get install -y caddy
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
EOF
sudo systemctl reload caddy
```

Caddy obtains and renews the certificate automatically and proxies
WebSockets without extra configuration.

### Option B: nginx

```sh
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo tee /etc/nginx/sites-available/immortal >/dev/null <<'EOF'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name relay.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
EOF
sudo ln -sfn /etc/nginx/sites-available/immortal /etc/nginx/sites-enabled/immortal
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d relay.example.com --redirect
```

`proxy_read_timeout` must exceed the client ping interval or idle WebSockets
drop every 60 seconds (nginx default).

### Verify end to end

```sh
curl -fsS -H 'Accept: application/nostr+json' https://relay.example.com/
```

Then connect a Nostr client to `wss://relay.example.com`, publish a note,
and read it back.

## 7. Backups

State lives in exactly one place: the Postgres database. Back up nothing
else (the binary and migrations are in version control/releases).

### Nightly logical dump (baseline — do this at minimum)

```sh
sudo mkdir -p /var/backups/immortal
sudo tee /etc/cron.d/immortal-backup >/dev/null <<'EOF'
30 3 * * * postgres pg_dump --format=custom --file=/var/backups/immortal/immortal-$(date +\%F).dump immortal && find /var/backups/immortal -name '*.dump' -mtime +14 -delete
EOF
```

Copy dumps off the machine (object storage, another host). A backup on the
same disk is not a backup. Restore test — do this once now, not during an
incident:

```sh
sudo -u postgres createdb immortal_restore_test
sudo -u postgres pg_restore -d immortal_restore_test /var/backups/immortal/immortal-<DATE>.dump
sudo -u postgres psql -d immortal_restore_test -c "SELECT count(*) FROM events;"
sudo -u postgres dropdb immortal_restore_test
```

### WAL notes (point-in-time recovery, optional)

`pg_dump` loses everything after the last dump. If losing up to a day of
events is unacceptable, enable continuous archiving:

- Set in `postgresql.conf`: `wal_level = replica`, `archive_mode = on`, and
  an `archive_command` that copies each WAL segment off-host (or use
  `pg_receivewal` from another machine).
- Take periodic base backups with `pg_basebackup`.
- Recovery: restore the base backup, provide `restore_command`, set a
  recovery target time.

This stays within one Postgres — it is configuration, not a new service.
For a single small relay, the nightly dump is usually the right trade.

## 8. Upgrade

Immortal's protocol tolerates disconnects: clients reconnect and re-send
`REQ`. A restart is a brief blip, not an outage.

```sh
# 1. Stage the new release beside the old one.
sudo mkdir -p /opt/immortal/releases/<NEW_VERSION>
sudo cp immortal /opt/immortal/releases/<NEW_VERSION>/immortal
sudo cp -r migrations /opt/immortal/releases/<NEW_VERSION>/migrations
sudo chmod 755 /opt/immortal/releases/<NEW_VERSION>/immortal

# 2. Apply new migrations (additive-first; old binary keeps working).
cd /opt/immortal/releases/<NEW_VERSION>
for f in migrations/*.sql; do  # the migrate subcommand skips applied files
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction -f "$f"
done

# 3. Flip and restart.
sudo ln -sfn /opt/immortal/releases/<NEW_VERSION> /opt/immortal/current
sudo systemctl restart immortal

# 4. Verify.
curl -fsS http://127.0.0.1:8080/health
journalctl -u immortal -n 20 --no-pager
```

On SIGTERM the relay stops accepting, drains in-flight admissions within
`IMMORTAL_SHUTDOWN_GRACE_SECONDS`, and exits; systemd's `TimeoutStopSec`
backs that with SIGKILL. Because `OK` is only sent after commit, a restart
can never acknowledge an unstored event.

## 9. Rollback

```sh
sudo ln -sfn /opt/immortal/releases/<OLD_VERSION> /opt/immortal/current
sudo systemctl restart immortal
curl -fsS http://127.0.0.1:8080/health
```

This works because migrations are additive-first: the old binary runs
against the newer schema. If a release ever requires a destructive
migration, its notes must say so, and rollback then means restoring the
pre-upgrade dump — which is why step 8 applies migrations only after a
fresh backup exists.

## 10. Routine checks

- `journalctl -u immortal --since -1h | grep -c error` — should be 0.
- `curl -fsS https://relay.example.com/health` from off-host (or a cheap
  external uptime monitor).
- Disk: `df -h /` and `sudo -u postgres psql -c "SELECT pg_size_pretty(pg_database_size('immortal'));"`.
- Backups exist and are recent: `ls -lh /var/backups/immortal | tail`.
