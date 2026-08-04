#!/bin/sh
# Manual native + wasm gate for MKT-SWP verification, client execution, and provider sessions.
set -eu

cd "$(dirname "$0")/.."

cargo test --locked -p immortal-core --features mkt-swp-verify --test mkt_swp_verification
cargo test --locked -p immortal-client --features mkt-swp-fixture-probe --test mkt_swp_client
cargo test --locked -p immortal-provider --no-default-features --test mkt_swp_provider
cargo check --locked -p immortal-provider --no-default-features --lib
cargo check --locked -p immortal-core --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-verify
cargo build --locked --release -p immortal-client --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-fixture-probe
cargo build --locked --release -p immortal-provider --target wasm32-unknown-unknown --lib --no-default-features --features mkt-swp-fixture-probe
secp_native=$(find target/wasm32-unknown-unknown/release/build -path '*/out/libsecp256k1.a' -exec dirname {} \; -quit)
test -n "$secp_native"
rustc --edition=2024 --target wasm32-unknown-unknown --crate-type=cdylib \
  crates/immortal-client/tests/wasm_mkt_swp_fixture_probe.rs -C opt-level=3 -C panic=abort \
  -L dependency=target/wasm32-unknown-unknown/release/deps \
  -L dependency=target/release/deps -L "native=$secp_native" \
  --extern immortal_client=target/wasm32-unknown-unknown/release/libimmortal_client.rlib \
  -o target/wasm32-unknown-unknown/release/mkt_swp_fixture_probe.wasm
node -e 'const fs=require("fs");const bytes=fs.readFileSync("target/wasm32-unknown-unknown/release/mkt_swp_fixture_probe.wasm");const module=new WebAssembly.Module(bytes);if(WebAssembly.Module.imports(module).length!==0)throw new Error("fixture probe has imports");const instance=new WebAssembly.Instance(module,{});if(instance.exports.immortal_mkt_swp_fixture_probe()!==0)throw new Error("fixture replay failed")'
rustc --edition=2024 --target wasm32-unknown-unknown --crate-type=cdylib \
  crates/immortal-provider/tests/wasm_mkt_swp_provider_fixture_probe.rs -C opt-level=3 -C panic=abort \
  -L dependency=target/wasm32-unknown-unknown/release/deps \
  -L dependency=target/release/deps -L "native=$secp_native" \
  --extern immortal_provider=target/wasm32-unknown-unknown/release/libimmortal_provider.rlib \
  -o target/wasm32-unknown-unknown/release/mkt_swp_provider_fixture_probe.wasm
node -e 'const fs=require("fs");const bytes=fs.readFileSync("target/wasm32-unknown-unknown/release/mkt_swp_provider_fixture_probe.wasm");const module=new WebAssembly.Module(bytes);if(WebAssembly.Module.imports(module).length!==0)throw new Error("provider fixture probe has imports");const instance=new WebAssembly.Instance(module,{});if(instance.exports.immortal_mkt_swp_provider_fixture_probe()!==0)throw new Error("provider fixture replay failed")'
