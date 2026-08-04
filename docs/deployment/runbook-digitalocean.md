# Runbook: DigitalOcean

The supported DigitalOcean deployment is one Debian 13 Droplet containing the
Immortal binary, apt Postgres, and Caddy or nginx. This is the canonical
single-box topology with DigitalOcean providing the VM and network edge.

DigitalOcean App Platform with Managed Postgres is deliberately **not** a
supported M5 path. Managed Postgres requires TLS, while the shipped binary has
no Postgres TLS backend. The owner has approved an optional
`tokio-postgres-rustls` feature, but approval is not implementation; do not
deploy that topology until the feature and its live managed-database proof
land together.

## 1. Create the Droplet

1. Create an amd64 or arm64 Droplet with the Debian 13 image.
2. Start with at least 1 GiB RAM and choose storage for the expected Postgres
   data plus the configured M7 media quota. Resize from measured use rather
   than guessing future scale.
3. Add an SSH key. Keep password login disabled.
4. Reserve an IP if the relay hostname must survive Droplet replacement.
5. Point `relay.example.com` at the Droplet IP.

## 2. Restrict the network

Create a DigitalOcean Cloud Firewall attached to the Droplet:

| Direction | Protocol | Port | Source/destination |
| --- | --- | ---: | --- |
| Inbound | TCP | 22 | operator IP ranges |
| Inbound | TCP | 80 | all IPv4/IPv6 |
| Inbound | TCP | 443 | all IPv4/IPv6 |
| Outbound | all | all | all |

Do not expose Postgres 5432 or Immortal 8080. The service unit binds both
application and database traffic to localhost. Use either the cloud firewall
or the Debian runbook's `ufw` step as the primary rule set; if you use both,
keep them identical.

## 3. Install Immortal

Connect to the Droplet and follow the canonical runbook end to end:

```sh
ssh root@<DROPLET_IP>
```

Continue with [`runbook-debian-vps.md`](runbook-debian-vps.md). Use the
committed systemd, proxy, environment, and backup assets rather than creating
provider-specific variants.

## 4. DigitalOcean backup choices

The required backup remains the runbook's logical `pg_dump` and paired M7
media tar, copied off the Droplet and restore-tested. DigitalOcean Droplet
backups or snapshots are a second layer, not a replacement: a VM image of
running Postgres is only crash-consistent, while the committed backup formats
are portable and testable.

Before an upgrade:

1. stop the relay, start `immortal-backup.service`, and verify success;
2. copy the new dump and same-timestamp media tar off the Droplet;
3. optionally take a Droplet snapshot;
4. follow the canonical symlink upgrade and schema-aware rollback procedure.

## 5. Verify

From outside DigitalOcean:

```sh
curl -fsS https://relay.example.com/health
curl -fsS -H 'Accept: application/nostr+json' \
  https://relay.example.com/
```

Publish and query an event over `wss://relay.example.com`. On the Droplet,
confirm that neither Postgres nor port 8080 is publicly listening and that the
backup timer is active:

```sh
sudo ss -ltnp
systemctl is-active immortal.service immortal-backup.timer
```

## Unsupported managed-platform path

Do not use App Platform + Managed Postgres with the current binary. Current
DigitalOcean connection details use `sslmode=require`; `tokio-postgres`
without a TLS connector fails rather than silently downgrading, which is the
correct fail-closed behavior. Trusted sources restrict reachability but do not
replace TLS.

When the approved optional TLS feature is implemented, this section can grow
into a separate runbook only after a disposable managed-cluster proof covers:

- TLS negotiation and credential redaction;
- migrations and `LISTEN/NOTIFY` through the managed endpoint;
- App Platform WebSocket upgrade and health behavior;
- backup/restore and rollback; and
- a manual, non-GitHub-billed conformance command.

Until then, the Droplet path above is the final DigitalOcean M5 runbook.

## Current platform references

- [DigitalOcean PostgreSQL connection details](https://docs.digitalocean.com/products/databases/postgresql/how-to/connect/)
