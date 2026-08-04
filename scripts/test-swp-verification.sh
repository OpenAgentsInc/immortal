#!/bin/sh
# Manual native + wasm gate for the MKT-SWP verification module.
set -eu

cd "$(dirname "$0")/.."

cargo test --locked --features mkt-swp-verify --test mkt_swp_verification
cargo check --locked --lib --no-default-features --features mkt-swp-verify
cargo check --locked --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-verify
