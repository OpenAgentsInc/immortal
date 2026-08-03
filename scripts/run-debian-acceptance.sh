#!/bin/sh
# Run the destructive acceptance only inside a disposable Debian 13 container.
set -eu

repository="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
runtime="${IMMORTAL_CONTAINER_RUNTIME:-}"

if test -z "${runtime}"; then
    if command -v container >/dev/null 2>&1 \
        && container system status 2>/dev/null | grep -q 'status.*running'; then
        runtime=container
    elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        runtime=podman
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        runtime=docker
    else
        echo "run-debian-acceptance: start Podman or Docker, or set IMMORTAL_CONTAINER_RUNTIME" >&2
        exit 1
    fi
fi

case "${runtime}" in
    container|podman|docker) ;;
    *)
        echo "run-debian-acceptance: runtime must be container, podman, or docker" >&2
        exit 1
        ;;
esac

"${runtime}" run --rm \
    --cpus 4 \
    --memory 4G \
    --env IMMORTAL_DISPOSABLE_CONTAINER=immortal-debian-acceptance \
    --volume "${repository}:/source:ro" \
    debian:13-slim \
    sh -c '
        mkdir /work
        cp /source/Cargo.toml /source/Cargo.lock /work/
        cp -R /source/src /source/migrations /source/tests /source/scripts /source/deploy /work/
        cd /work
        IMMORTAL_DEBIAN_ACCEPTANCE=1 ./scripts/test-debian.sh
    '
