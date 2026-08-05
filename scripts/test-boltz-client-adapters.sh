#!/bin/sh
set -eu

export LC_ALL=C

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

unformatted=$(gofmt -l "$root/adapters/boltz-client-go")
if [ -n "$unformatted" ]; then
    echo "Go adapter files require gofmt:" >&2
    echo "$unformatted" >&2
    exit 1
fi

(
    cd "$root/adapters/boltz-client-go"
    go test ./...
    go vet ./...
)

node --check "$root/adapters/boltz-web-app/adapter.mjs"
node --check "$root/adapters/boltz-web-app/adapter.test.mjs"
(
    cd "$root/adapters/boltz-web-app"
    node --test adapter.test.mjs
)
