#!/bin/sh
# Complete manual M1-M7, M10, and adopted M12 gate. No billed runner is used.
set -eu

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
if cargo tree --locked -p immortal-relay --edges normal --prefix none | grep -Eq '^immortal-(client|provider) '; then
    echo "immortal-relay must not depend on immortal-client or immortal-provider" >&2
    exit 1
fi
cargo check --locked --workspace --all-targets
cargo test --locked -p immortal-core --test mkt_fixtures
cargo test --locked -p immortal-core --test mkt_immutability_model
cargo test --locked -p immortal-core --test mkt_common_fixtures
cargo test --locked -p immortal-core --test mkt_closing_fixtures
cargo test --locked -p immortal-core --test mkt_swp_profile
cargo test --locked -p immortal-core --test mkt_pfi_profile
cargo test --locked -p immortal-core --test mkt_mint_profile
cargo test --locked -p immortal-core --test mkt_p2p_profile
cargo test --locked -p immortal-client --test tbdex_legacy_fixtures
./scripts/test-swp-verification.sh
cargo test --locked -p immortal-relay --test mkt_swp_coordination
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps --all-features

sh -n deploy/backup/immortal-backup
sh -n scripts/test-debian.sh
sh -n scripts/run-debian-acceptance.sh
python3 -c 'compile(open("scripts/debian-acceptance-client.py", encoding="utf-8").read(), "scripts/debian-acceptance-client.py", "exec")'
sh -n scripts/export-contract.sh
./scripts/export-contract.sh --check
git diff --check

./scripts/test-postgres.sh
./scripts/run-debian-acceptance.sh
