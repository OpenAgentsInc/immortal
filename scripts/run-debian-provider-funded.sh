#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
receipt_relative_path=""

usage() {
    echo "usage: scripts/run-debian-provider-funded.sh --receipt docs/conformance/records/<name>.json" >&2
}

if test "$#" != 2 || test "$1" != --receipt; then
    usage
    exit 2
fi
receipt_relative_path="$2"
case "${receipt_relative_path}" in
    docs/conformance/records/*.json)
        case "${receipt_relative_path}" in
            *..* | *'//'*)
                echo "run-debian-provider-funded: receipt path is invalid" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        echo "run-debian-provider-funded: receipt must be under docs/conformance/records" >&2
        exit 2
        ;;
esac

receipt_path="${repository}/${receipt_relative_path}"
if test -e "${receipt_path}"; then
    echo "run-debian-provider-funded: refusing to overwrite ${receipt_relative_path}" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "run-debian-provider-funded: start Docker before running the disposable Debian gate" >&2
    exit 1
fi
if ! git -C "${repository}" diff --quiet || ! git -C "${repository}" diff --cached --quiet; then
    echo "run-debian-provider-funded: commit or stash tracked changes before recording evidence" >&2
    exit 1
fi

source_commit="$(git -C "${repository}" rev-parse HEAD)"
receipt_directory="$(mktemp -d /tmp/immortal-debian-provider-receipt.XXXXXX)"
case "$(basename "${receipt_directory}")" in
    immortal-debian-provider-receipt.*) ;;
    *)
        echo "run-debian-provider-funded: temporary receipt directory is invalid" >&2
        exit 1
        ;;
esac
container_log="${receipt_directory}/container.log"

if ! docker run --rm \
    --privileged \
    --cpus 4 \
    --memory 6G \
    --volume "${repository}:/source:ro" \
    --volume "${receipt_directory}:${receipt_directory}" \
    --env IMMORTAL_DEBIAN_PROVIDER_FUNDED_ACCEPTANCE=1 \
    --env IMMORTAL_DISPOSABLE_CONTAINER=immortal-debian-provider-funded \
    --env IMMORTAL_DEBIAN_PROVIDER_SOURCE_COMMIT="${source_commit}" \
    --env IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY="${receipt_directory}" \
    --env TMPDIR="${receipt_directory}" \
    debian:13-slim \
    sh -ec '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >/dev/null
        apt-get install -y --no-install-recommends \
            ca-certificates cargo build-essential python3-minimal docker-cli docker-compose docker.io >/dev/null
        mkdir /work
        cp /source/Cargo.toml /source/Cargo.lock /source/Dockerfile /source/.dockerignore /work/
        cp -R /source/crates /source/migrations /source/scripts /source/tests /source/adapters /source/nips /work/
        dockerd_log=/tmp/immortal-debian-provider-dockerd.log
        dockerd_pid=
        cleanup() {
            exit_status=$?
            trap - EXIT HUP INT TERM
            if test -n "${dockerd_pid}" && kill -0 "${dockerd_pid}" 2>/dev/null; then
                kill -TERM "${dockerd_pid}"
                wait "${dockerd_pid}" || true
            fi
            exit "${exit_status}"
        }
        trap cleanup EXIT HUP INT TERM
        mkdir /var/lib/immortal-dockerd
        dockerd --host unix:///var/run/docker.sock \
            --data-root /var/lib/immortal-dockerd \
            --pidfile /var/run/immortal-dockerd.pid >"${dockerd_log}" 2>&1 &
        dockerd_pid=$!
        attempts=0
        until docker info >/dev/null 2>&1; do
            attempts=$((attempts + 1))
            if test "${attempts}" -ge 120 || ! kill -0 "${dockerd_pid}" 2>/dev/null; then
                sed -n "1,160p" "${dockerd_log}" >&2
                exit 1
            fi
            sleep 1
        done
        cd /work
        scripts/test-debian-provider-funded.sh
    ' >"${container_log}" 2>&1; then
    sed -n '1,200p' "${container_log}" >&2
    echo "run-debian-provider-funded: Debian gate failed; retained ${receipt_directory}" >&2
    exit 1
fi

receipt_result="${receipt_directory}/result.json"
if test ! -f "${receipt_result}"; then
    sed -n '1,200p' "${container_log}" >&2
    echo "run-debian-provider-funded: the Debian gate produced no receipt" >&2
    exit 1
fi
mv "${receipt_result}" "${receipt_path}"
rm -f "${container_log}"
rmdir "${receipt_directory}"
echo "run-debian-provider-funded: wrote ${receipt_relative_path}"
