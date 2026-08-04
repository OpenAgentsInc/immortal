#!/bin/sh
# Complete manual M1-M7, M10, and adopted M12 gate. No billed runner is used.
set -eu

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --test mkt_fixtures
cargo test --locked --test mkt_immutability_model
cargo test --locked --test mkt_common_fixtures
cargo test --locked --test mkt_closing_fixtures
cargo test --locked --test mkt_swp_profile
cargo test --locked --test mkt_pfi_profile
cargo test --locked --test tbdex_legacy_fixtures
./scripts/test-swp-verification.sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets --features mkt-swp-verify -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --features mkt-swp-verify

sh -n deploy/backup/immortal-backup
sh -n scripts/test-debian.sh
sh -n scripts/run-debian-acceptance.sh
python3 -c 'compile(open("scripts/debian-acceptance-client.py", encoding="utf-8").read(), "scripts/debian-acceptance-client.py", "exec")'
sh -n scripts/export-contract.sh
./scripts/export-contract.sh --check
git diff --check

./scripts/test-postgres.sh
./scripts/run-debian-acceptance.sh
