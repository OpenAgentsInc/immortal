#!/bin/sh
# Manual native + wasm gate for the transport-neutral project client.
set -eu

cd "$(dirname "$0")/.."

cargo test --locked -p immortal-client --test openagents_project_fixtures
cargo check --locked -p immortal-client --lib --no-default-features
cargo check --locked -p immortal-client --target wasm32-unknown-unknown --lib --no-default-features
