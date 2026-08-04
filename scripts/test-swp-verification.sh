#!/bin/sh
# Manual native + wasm gate for MKT-SWP verification and client execution.
set -eu

cd "$(dirname "$0")/.."

cargo test --locked --features mkt-swp-verify --test mkt_swp_verification
cargo test --locked --features mkt-swp-verify --test mkt_swp_client
cargo check --locked --lib --no-default-features --features mkt-swp-verify
cargo check --locked --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-verify
