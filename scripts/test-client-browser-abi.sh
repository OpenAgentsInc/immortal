#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

source_revision="$(git rev-parse HEAD)"
IMMORTAL_SOURCE_REVISION="$source_revision" \
  cargo build --locked --release -p immortal-client-web --target wasm32-unknown-unknown
IMMORTAL_EXPECTED_SOURCE_REVISION="$source_revision" \
  node --test adapters/immortal-client-web/adapter.test.mjs
cargo test --locked -p immortal-client-web
cargo test --locked -p immortal-client browser_api::tests
