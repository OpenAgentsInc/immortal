# Immortal Agent Rules

Read `README.md` first.

## Rules

1. **One binary and one Postgres database.** Do not add a service, a
   broker, a cache, a sync engine, or a second database. If a feature needs
   another running service, the feature is wrong.
2. **Use only these direct dependencies:** `tokio`, `tokio-tungstenite`,
   `tokio-postgres`, `secp256k1`, `sha2`, `serde`, `serde_json`. To add a
   dependency, get owner approval first. Record the approval in this file.
3. **Write the Nostr primitives in this repository.** Put the event, tag,
   filter, canonical ID, replacement, and deletion logic in `src/domain/`.
   Do not use a third-party Nostr crate.
4. **Use prepared SQL statements only.** Do not build SQL from strings at
   run time.
5. **Set limits.** Limit frame size, subscriptions per connection, filters
   per REQ, and query cost. Apply rate limits per IP and per pubkey.
6. **Fail closed.** Send `OK` only after the database commit. If a process
   cannot become current, it must close its connections.
7. **Keep ephemeral events out of storage.** Kinds 20000–29999 never go to
   a table.
8. **Test against the NIP specifications in `nips/`.** That directory
   holds our pinned copies from three upstream sources (official, block,
   openagents) — see `nips/README.md` for the sync and review process.
   Keep a fixture corpus for each implemented NIP. A protocol change
   without a fixture is not complete. A sync commit never changes the
   implementation by itself.
9. **Keep the deployment test green.** A new Debian server, Postgres from
   the package manager, and this binary must make a running relay in
   minutes, with only the README as the guide.
10. **No secrets in this repository.** This repository is public.

## License rule

This repository is CC0-1.0. Dependencies with MIT, Apache, or BSD licenses
are permitted. Do not copy code with an incompatible license.

## Workflow

Work on `main`. Commit and push completed work.
