#!/usr/bin/env bash
# Check the repository-enforced security boundaries from AGENTS.md.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
  echo "test-security-boundaries: $1" >&2
  exit 1
}

assert_direct_dependencies() {
  package="$1"
  shift
  actual="$(
    cargo tree --locked -p "${package}" --edges normal --prefix none --depth 1 |
      tail -n +2 |
      awk '{print $1}' |
      LC_ALL=C sort
  )"
  expected="$(printf '%s\n' "$@" | LC_ALL=C sort)"
  if test "${actual}" != "${expected}"; then
    printf 'test-security-boundaries: %s direct dependencies changed\nexpected:\n%s\nactual:\n%s\n' \
      "${package}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

test "$(sed -n 's/^license = "\([^"]*\)"$/\1/p' Cargo.toml)" = "CC0-1.0" ||
  fail "workspace license is not CC0-1.0"
if find .github/workflows -type f -print -quit 2>/dev/null | grep -q .; then
  fail "GitHub workflows are forbidden"
fi

assert_direct_dependencies immortal-core \
  secp256k1 serde serde_json sha2
assert_direct_dependencies immortal-client \
  immortal-core secp256k1 serde serde_json sha2
assert_direct_dependencies immortal-client-web \
  immortal-client
assert_direct_dependencies immortal-relay \
  immortal-core secp256k1 serde serde_json sha2 tokio tokio-postgres tokio-tungstenite
assert_direct_dependencies immortal-provider \
  immortal-client immortal-core secp256k1 serde serde_json sha2 tokio tokio-postgres tokio-tungstenite

relay_tree="$(cargo tree --locked -p immortal-relay --edges normal --prefix none)"
if printf '%s\n' "${relay_tree}" | awk '{print $1}' |
  grep -Exq '(immortal-client|immortal-provider|tokio-rustls|rustls|bitcoin|nostr)'; then
  fail "relay dependency closure crossed the client, provider, TLS, Bitcoin, or Nostr boundary"
fi
if printf '%s\n' "$(cargo tree --locked -p immortal-provider --edges normal --prefix none)" |
  awk '{print $1}' | grep -qx tokio-rustls; then
  fail "default provider build unexpectedly includes the optional TLS chain"
fi
if ! cargo tree --locked -p immortal-provider --no-default-features --features lnd \
  --edges normal --prefix none | awk '{print $1}' | grep -qx tokio-rustls; then
  fail "the explicit LND feature does not include its approved TLS boundary"
fi

if rg -n -U '\.(query|query_one|query_opt|execute)\(\s*(r#*|")' \
  crates/immortal-relay/src crates/immortal-provider/src -g '*.rs'; then
  fail "runtime Postgres call contains a direct SQL string instead of a prepared statement"
fi
if rg -n -i \
  '(seed|private_key|preimage|macaroon|claim_key|refund_key)[[:space:]]+(text|bytea|jsonb)' \
  migrations; then
  fail "a product schema contains a custody-material column"
fi

if git grep -I -n -E -- \
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+' \
  -- . ':!tests/fixtures/**' ':!nips/**' ':!projects/**' ':!docs/inspiration/**'; then
  fail "a common live-secret shape appears outside pinned fixtures or source lanes"
fi

echo "test-security-boundaries: AGENTS.md dependency, custody, SQL, secret, license, and automation boundaries passed"
