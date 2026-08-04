#!/bin/sh
# Manual native + wasm gate for MKT-SWP verification and client execution.
set -eu

cd "$(dirname "$0")/.."

cargo test --locked --features mkt-swp-verify --test mkt_swp_verification
cargo test --locked --features mkt-swp-fixture-probe --test mkt_swp_client
cargo check --locked --lib --no-default-features --features mkt-swp-verify
cargo build --locked --release --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-fixture-probe
secp_native=$(find target/wasm32-unknown-unknown/release/build -path '*/out/libsecp256k1.a' -exec dirname {} \; -quit)
test -n "$secp_native"
rustc --edition=2024 --target wasm32-unknown-unknown --crate-type=cdylib \
  tests/wasm_mkt_swp_fixture_probe.rs -C opt-level=3 -C panic=abort \
  -L dependency=target/wasm32-unknown-unknown/release/deps \
  -L dependency=target/release/deps -L "native=$secp_native" \
  --extern immortal=target/wasm32-unknown-unknown/release/libimmortal.rlib \
  -o target/wasm32-unknown-unknown/release/mkt_swp_fixture_probe.wasm
node -e 'const fs=require("fs");const bytes=fs.readFileSync("target/wasm32-unknown-unknown/release/mkt_swp_fixture_probe.wasm");const module=new WebAssembly.Module(bytes);if(WebAssembly.Module.imports(module).length!==0)throw new Error("fixture probe has imports");const instance=new WebAssembly.Instance(module,{});if(instance.exports.immortal_mkt_swp_fixture_probe()!==0)throw new Error("fixture replay failed")'
