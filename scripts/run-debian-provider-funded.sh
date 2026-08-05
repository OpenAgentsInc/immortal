#!/bin/sh
set -eu
umask 077

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
if test -n "$(git -C "${repository}" status --porcelain --untracked-files=all)"; then
    echo "run-debian-provider-funded: commit, stash, or remove changes before recording evidence" >&2
    exit 1
fi

receipt_pending_path="${receipt_path}.pending-$(LC_ALL=C od -An -N 8 -tx1 /dev/urandom | tr -d ' \n')"
if test -e "${receipt_pending_path}"; then
    echo "run-debian-provider-funded: pending receipt path already exists" >&2
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
chmod 0700 "${receipt_directory}"
controller_directory="$(mktemp -d /tmp/immortal-debian-provider-controller.XXXXXX)"
case "$(basename "${controller_directory}")" in
    immortal-debian-provider-controller.*) ;;
    *)
        echo "run-debian-provider-funded: controller directory is invalid" >&2
        exit 1
        ;;
esac
chmod 0700 "${controller_directory}"
controller_log="${controller_directory}/container.log"
failure_log="${receipt_directory}/failure.log"
outer_container_name="immortal-debian-provider-$(LC_ALL=C od -An -N 8 -tx1 /dev/urandom | tr -d ' \n')"
outer_container_id=""
failure_reason="Debian gate failed"

cleanup() {
    exit_status=$?
    trap - 0 HUP INT TERM
    cleanup_failed=false
    if test "${exit_status}" -ne 0; then
        if test -n "${outer_container_id}" \
            && ! docker rm --force "${outer_container_id}" >>"${controller_log}" 2>&1; then
            cleanup_failed=true
        fi
        rm -f "${receipt_pending_path}"
        if test -n "${receipt_directory}" && test -d "${receipt_directory}"; then
            rm -f "${receipt_directory}/result.json"
            : >"${failure_log}"
            if test -f "${controller_log}"; then
                head -c 65536 "${controller_log}" | sed -n '1,200p' >"${failure_log}"
            fi
            chmod 0600 "${failure_log}"
            sed -n '1,200p' "${failure_log}" >&2
            echo "run-debian-provider-funded: ${failure_reason}; retained bounded console ${failure_log}" >&2
        else
            echo "run-debian-provider-funded: ${failure_reason}; receipt directory was removed before failure cleanup" >&2
        fi
    fi
    if test -n "${controller_directory}" && ! rm -f "${controller_log}"; then
        cleanup_failed=true
    fi
    if test -n "${controller_directory}" && ! rmdir "${controller_directory}"; then
        cleanup_failed=true
    fi
    if test "${cleanup_failed}" = true; then
        echo "run-debian-provider-funded: controller cleanup failed; no receipt was published" >&2
    fi
    exit "${exit_status}"
}

handle_signal() {
    failure_reason="Debian gate interrupted"
    exit 1
}

trap cleanup 0
trap handle_signal HUP INT TERM

if ! outer_container_id="$(docker create \
    --name "${outer_container_name}" \
    --privileged \
    --cpus 4 \
    --memory 6G \
    --volume "${repository}:/source:ro" \
    --volume "${receipt_directory}:${receipt_directory}" \
    --env IMMORTAL_DEBIAN_PROVIDER_FUNDED_ACCEPTANCE=1 \
    --env IMMORTAL_DISPOSABLE_CONTAINER=immortal-debian-provider-funded \
    --env IMMORTAL_DEBIAN_PROVIDER_SOURCE_COMMIT="${source_commit}" \
    --env IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY="${receipt_directory}" \
    debian:13-slim \
    sh -ec '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >/dev/null
        apt-get install -y --no-install-recommends \
            ca-certificates cargo build-essential curl python3-minimal docker-cli docker-compose docker.io \
            golang-go nodejs >/dev/null
        for command_name in cargo curl docker go node; do
            command -v "${command_name}" >/dev/null
        done
        docker compose version >/dev/null
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
    ' 2>"${controller_log}")"; then
    failure_reason="Debian gate container creation failed"
    exit 1
fi
if ! printf '%s\n' "${outer_container_id}" | grep -Eq '^[0-9a-f]{64}$'; then
    failure_reason="Debian gate returned an invalid container identity"
    exit 1
fi
if ! docker start --attach "${outer_container_id}" >>"${controller_log}" 2>&1; then
    failure_reason="Debian gate failed"
    exit 1
fi

receipt_result="${receipt_directory}/result.json"
if test ! -f "${receipt_result}"; then
    failure_reason="Debian gate produced no receipt"
    exit 1
fi
if ! docker rm "${outer_container_id}" >>"${controller_log}" 2>&1; then
    failure_reason="Debian gate exact container cleanup failed"
    exit 1
fi
if docker inspect "${outer_container_id}" >/dev/null 2>&1; then
    failure_reason="Debian gate exact container remains after cleanup"
    exit 1
fi
outer_container_id=""
if ! mv "${receipt_result}" "${receipt_pending_path}"; then
    failure_reason="Debian gate receipt staging failed"
    exit 1
fi
if ! rmdir "${receipt_directory}"; then
    failure_reason="Debian gate receipt directory cleanup failed"
    exit 1
fi
receipt_directory=""
if ! rm -f "${controller_log}"; then
    failure_reason="Debian gate controller log cleanup failed"
    exit 1
fi
if ! rmdir "${controller_directory}"; then
    failure_reason="Debian gate controller directory cleanup failed"
    exit 1
fi
controller_directory=""
mv "${receipt_pending_path}" "${receipt_path}"
