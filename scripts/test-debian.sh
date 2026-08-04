#!/bin/sh
# Destructive only inside a fresh Debian 13 acceptance container.
set -eu

cd "$(dirname "$0")/.."

if test "${IMMORTAL_DEBIAN_ACCEPTANCE:-}" != 1; then
    echo "test-debian: set IMMORTAL_DEBIAN_ACCEPTANCE=1 in a disposable container" >&2
    exit 1
fi
if test "${IMMORTAL_DISPOSABLE_CONTAINER:-}" != immortal-debian-acceptance; then
    echo "test-debian: refusing to modify a non-container host" >&2
    exit 1
fi
. /etc/os-release
if test "${ID}" != debian || test "${VERSION_ID}" != 13; then
    echo "test-debian: requires a fresh Debian 13 container" >&2
    exit 1
fi
if test "$(id -u)" != 0; then
    echo "test-debian: requires root inside the disposable container" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    postgresql curl ca-certificates cargo build-essential python3-minimal systemd

service postgresql start
runuser -u postgres -- psql --set=ON_ERROR_STOP=1 --command \
    "CREATE ROLE immortal LOGIN PASSWORD 'immortal_acceptance_only';"
runuser -u postgres -- createdb --owner=immortal immortal

cargo build --locked --release -p immortal-relay --bin immortal

useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin immortal
usermod --append --groups immortal postgres
install -d -o root -g root -m 0755 /opt/immortal/releases/acceptance
install -o root -g root -m 0755 target/release/immortal \
    /opt/immortal/releases/acceptance/immortal
ln -sfn /opt/immortal/releases/acceptance /opt/immortal/current
install -d -o root -g immortal -m 0750 /etc/immortal
install -o root -g immortal -m 0640 deploy/immortal.env.example \
    /etc/immortal/immortal.env
install -d -o postgres -g postgres -m 0700 /var/backups/immortal
install -d -o immortal -g immortal -m 0750 /var/lib/immortal/media
install -o root -g root -m 0755 deploy/backup/immortal-backup \
    /usr/local/sbin/immortal-backup
install -o root -g root -m 0644 deploy/systemd/immortal.service \
    /etc/systemd/system/immortal.service
install -o root -g root -m 0644 deploy/backup/immortal-backup.service \
    /etc/systemd/system/immortal-backup.service
install -o root -g root -m 0644 deploy/backup/immortal-backup.timer \
    /etc/systemd/system/immortal-backup.timer
systemd-analyze verify \
    /etc/systemd/system/immortal.service \
    /etc/systemd/system/immortal-backup.service \
    /etc/systemd/system/immortal-backup.timer
relay_log="$(mktemp /tmp/immortal-debian-acceptance.XXXXXX)"
relay_pid=

cleanup() {
    if test -n "${relay_pid}" && kill -0 "${relay_pid}" 2>/dev/null; then
        kill -TERM "${relay_pid}"
        wait "${relay_pid}" || true
    fi
    rm -f -- "${relay_log}"
}
trap cleanup EXIT HUP INT TERM

DATABASE_URL='postgres://immortal:immortal_acceptance_only@127.0.0.1:5432/immortal' \
IMMORTAL_PORT=18080 \
IMMORTAL_RELAY_URL=ws://127.0.0.1:18080 \
IMMORTAL_MEDIA_ROOT=/var/lib/immortal/media \
    ./target/release/immortal >"${relay_log}" 2>&1 &
relay_pid=$!

attempt=0
until curl -fsS http://127.0.0.1:18080/health | grep -q '"status":"ok"'; do
    attempt=$((attempt + 1))
    if test "${attempt}" -ge 100 || ! kill -0 "${relay_pid}" 2>/dev/null; then
        sed -n '1,120p' "${relay_log}" >&2
        exit 1
    fi
    sleep 0.1
done
curl -fsS -H 'Accept: application/nostr+json' \
    http://127.0.0.1:18080/ | grep -q '"supported_nips"'
python3 scripts/debian-acceptance-client.py

kill -TERM "${relay_pid}"
wait "${relay_pid}"
relay_pid=

runuser -u postgres -- /usr/local/sbin/immortal-backup
backup="$(find /var/backups/immortal -type f -name 'immortal-*.dump' -print -quit)"
media_backup="$(find /var/backups/immortal -type f -name 'immortal-media-*.tar' -print -quit)"
test -n "${backup}"
test -n "${media_backup}"
tar --list --file="${media_backup}" >/dev/null
runuser -u postgres -- createdb immortal_restore_test
runuser -u postgres -- pg_restore --dbname=immortal_restore_test "${backup}"
test "$(runuser -u postgres -- psql --tuples-only --no-align \
    --dbname=immortal_restore_test \
    --command='SELECT count(*) FROM nostr_event;')" = 1
runuser -u postgres -- dropdb immortal_restore_test

echo "test-debian: fresh Debian 13 relay and backup/restore acceptance passed"
