# Immortal Agent Rules

Read `README.md` and `docs/MONOREPO.md` first.

## Product rules

1. **One binary and one Postgres database per product.** Do not add a
   broker, cache, sync engine, or second database. The provider may connect
   to the operator's declared bitcoind and Lightning rail nodes. The relay
   never connects to a rail node.
2. **Use each crate's owner-approved dependency allowlist.** Versions are
   pinned once in the root `workspace.dependencies` table.
   - `immortal-core`: `secp256k1`, `sha2`, `serde`, `serde_json`.
   - `immortal-client`: `secp256k1`, `sha2`, `serde`, `serde_json`, plus
     `immortal-core`.
   - `immortal-relay`: `tokio`, `tokio-tungstenite`, `tokio-postgres`,
     `secp256k1`, `sha2`, `serde`, `serde_json`, plus `immortal-core`.
   - `immortal-provider`: the same seven external crates as the relay, plus
     the workspace core and client crates when its implementation needs
     them.

   To add a dependency, get owner approval first and record it here.

   Approved additions:
   - `tokio-postgres-rustls` with its `rustls` chain (owner approval,
     2026-08-03). Purpose: an optional TLS backend for managed Postgres
     services that require TLS. It may also support a provider rail that
     genuinely requires TLS, such as LND REST. Add it only with that
     deployment path, behind a feature flag. The Debian single-box, Google
     Cloud Unix-socket, bitcoind-localhost, and CLN Unix-socket paths do not
     use it.

   MuSig2 decision (2026-08-05): retain `secp256k1` 0.31.1 and add no
   dependency. BIP-327 orchestration, nonce lifecycle, scalar arithmetic,
   partial verification, and aggregation are implemented in-repo over the
   allowlisted crate's point/tweak operations and pinned official vectors.
3. **Write protocol primitives in this repository.** Nostr event, tag,
   filter, canonical ID, replacement, and deletion logic belongs in
   `crates/immortal-core/src/domain/`. Bitcoin and Lightning verification
   and construction primitives belong in `immortal-core`, fixture-tested
   against the pinned BIP and BOLT vectors. Do not use a third-party Nostr
   or Bitcoin crate.
4. **Use prepared SQL statements only.** Do not build SQL from strings at
   run time. This applies independently to every product database.
5. **Set limits.** Bound inputs, connections, subscriptions, filters, query
   cost, queues, retries, and external-rail work. Apply the relevant rate
   limits per IP, pubkey, or provider identity.
6. **Fail closed.** The relay sends `OK` only after the database commit. A
   process that cannot remain current closes affected connections. Provider
   rail failures and unresolved timelocks surface explicitly and never
   become success states.
7. **Keep relay ephemeral events out of storage.** Kinds 20000–29999 never
   go to a relay table.
8. **Test against the pinned specifications in `nips/`.** The directory
   holds official, Block, and OpenAgents source lanes. Keep a fixture corpus
   for every implemented protocol. A protocol change without a fixture is
   incomplete. A sync commit never changes implementation by itself.
9. **Keep a deployment test per product green.** A fresh Debian server plus
   the product's declared prerequisites must yield a running instance in
   minutes using only the README and runbook. The relay requires apt
   Postgres. The provider declares Postgres, bitcoind, and its supported
   Lightning node and plugins.
10. **Make the custody boundary a build fact.** `immortal-relay` never
    depends on `immortal-client` or `immortal-provider` and never links
    wallet, spend-signing, claim/refund-key, unreleased-preimage, or
    node-control code. `immortal-core` contains pure logic and no key
    storage. Provider seeds, spend keys, unreleased preimages, and node
    credentials live only in operator-owned files or environment with mode
    0600 where applicable, never in the provider database. Review
    `cargo tree -p immortal-relay` for this boundary.
11. **No secrets in this repository.** This repository is public.
12. **No GitHub workflows or GitHub-billed automation.** Do not add or use
    GitHub Actions, `.github/workflows/`, or a conformance/deployment path
    that requires GitHub billing. Required checks run manually on a
    contributor machine or explicitly owner-approved non-GitHub
    infrastructure.

## License rule

This repository is CC0-1.0. Dependencies with MIT, Apache, or BSD licenses
are permitted. Do not copy code with an incompatible license.

## Working agreement

Keep each packet scoped to one product or shared primitive boundary. Commit
and push completed work only after that packet's native, wasm where
applicable, conformance, contract, and deployment gates pass.
