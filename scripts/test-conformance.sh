#!/bin/sh
# Complete manual M1-M7 gate. No GitHub workflow or billed runner is used.
set -eu

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --test mkt_fixtures
cargo test --locked --test mkt_immutability_model
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps

sh -n deploy/backup/immortal-backup
sh -n scripts/test-debian.sh
sh -n scripts/run-debian-acceptance.sh
python3 -c 'compile(open("scripts/debian-acceptance-client.py", encoding="utf-8").read(), "scripts/debian-acceptance-client.py", "exec")'
git diff --check

./scripts/test-postgres.sh
./scripts/run-debian-acceptance.sh
