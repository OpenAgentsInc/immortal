# Boltz Ecosystem

## Source

| Field | Value |
| --- | --- |
| Organization | <https://github.com/BoltzExchange> |
| Local review set | `~/work/projects/repos/boltz/` (31 public repositories) |
| `boltz-backend` | `4d131ef8562eea25ab687bcc75a17ce899110b66` (v3.13.0, AGPL-3.0) |
| `boltz-core` | `a932d49c4daaeae3d7940dc1519bf77ef92e6dc1` (v5.0.0, MIT) |
| `boltz-client` | `746f73c5ecbd3621f628f60108a404ef26f0de95` (MIT) |
| `boltz-web-app` | `dd9c2df26db54a2554dc1e628b095ce856c0d9de` (v2.2.1, AGPL-3.0) |
| `hold` | `14c3568d2b9be7af23df69a4dc579dd198428f1d` (MIT) |
| Documentation | `0d7cb95ac48742f05a097ab47df44c64bbdc519c` |
| Review date | 2026-08-04 |

This is a mixed-license ecosystem. Immortal may learn protocol behavior from
the whole review set. It may copy only license-compatible material, with the
source, commit, path, and license recorded as required by this directory's
rules. In particular, the AGPL backend and web application are not code donors
for this CC0 repository. No Boltz code is copied by this review.

## What it is

Boltz is a noncustodial atomic-swap system spanning Bitcoin, Lightning,
Liquid, and additional supported rails. Its strongest law is not its HTTP API;
it is that a client verifies the lock script or Taproot tree, amounts, payment
hash, timelocks, and claim/refund paths before funding. Hash/preimage coupling
binds the two legs. Cooperative MuSig2 key-path claims optimize the happy path,
while script-path claims and refunds preserve a unilateral exit.

The current product has a central provider API and operator backend, but its
settlement physics do not require Immortal to become custodian. For OpenAgents,
Boltz is the atomic-settlement profile inside the **Liquidity Market**. Immortal
should absorb the noncustodial coordination surface—provider discovery,
quotes, reservations, lifecycle enforcement, evidence, timers, recovery, and
compatibility APIs—while wallets and independent liquidity providers retain
funds and spend authority.

The intended translation is:

```text
public ProviderProfile / Offering
              |
wallet -- private RFQ --> provider candidates
wallet <-- signed Quote -- provider candidates
              |
       exact Quote acceptance
              |
   rail-specific lock / invoice proof
              |
 sequenced Status -- claim or refund -- Close

Immortal coordinates and verifies; the underlying rail settles.
```

## Borrow

| Item | Upstream location | How Immortal adapts it |
| --- | --- | --- |
| Explicit submarine, reverse, and chain-swap lifecycles | `boltz-backend/docs/lifecycle.md`, `boltz-backend/lib/swap/` | Define an MKT-SWP state machine with legal transitions, terminal outcomes, timeouts, and replay/idempotency rules. Persist accepted coordination state transactionally in Postgres. |
| “Don't trust, verify” funding law | `boltz-backend/docs/dont-trust-verify.md` | The transport-neutral client re-derives scripts/trees, addresses, payment-hash bindings, amounts, fees, and timeout policy before exposing a fund action. Relay acceptance never authorizes funding. |
| HTLC, Taproot, MuSig2, claim, and refund primitives | `boltz-core/lib/swap/`, `boltz-core/lib/musig/`, `boltz-core/lib/liquid/swap/` | Use the behavior and MIT test corpus as design inputs for Immortal-owned primitives and fixtures. Do not add `boltz-core` as a Nostr dependency or translate TypeScript blindly. |
| Cooperative happy path plus unilateral fallback | `boltz-core/lib/swap/Claim.ts`, `boltz-core/lib/swap/Refund.ts`, `boltz-core/lib/swap/ReverseSwapTree.ts` | Every quoted route binds both the cooperative path and the independently executable noncooperative exit. A route without an explainable worst-case refund graph fails closed. |
| Hold-invoice reverse-swap mechanics | `hold/src/`, `boltz-backend/lib/swap/InvoiceNursery.ts` | Model hold state and expiry explicitly. Provider node credentials stay provider-side; Immortal handles signed state, evidence references, due timers, and recovery messages. |
| Bounded pair, fee, and limit discovery | `boltz-backend/docs/api-v2.md`, `docs/swap-limits-and-fees.md` | Express slow-changing provider capabilities as addressable profiles and short-lived executable Offerings. Rebind fees, limits, pair, network, and expiry in every signed Quote. |
| Status stream and recovery | `boltz-backend/docs/api-v2.md`, `boltz-backend/docs/swap-restore.md`, `boltz-client/internal/nursery/` | Use private, sequenced, monotonic Status events plus local replay. Missing events, reconnects, duplicate orders, and provider crashes must converge on claim, refund, or an explicit unresolved state. |
| Autoswap policy as client-owned choice | `boltz-client/internal/autoswap/` | Keep route selection, budget, acceptable fees, confirmation policy, and custody tolerance in the wallet/router. Immortal may calculate candidates but cannot silently spend or choose trust policy. |
| REST/WebSocket compatibility | `boltz-backend/docs/api-v2.md` | After native NIP-MKT works, expose a bounded compatibility surface from the same Immortal binary so existing Boltz clients can reach provider sessions without making HTTP the canonical protocol. |
| Adversarial regtest | `boltz-client` regtest tests, `BoltzExchange/regtest` | Build a manual multi-provider lab covering stale quotes, double reservation, RBF, reorg, dropped status, crash/restart, noncooperation, claim, refund, and secret leakage. No GitHub workflow is part of the proof. |

## Reject

| Item | Reason |
| --- | --- |
| Copying or linking the AGPL backend/web application into Immortal | Incompatible product and licensing boundary for this CC0 implementation. Learn observable behavior; write Immortal's implementation from the pinned NIPs and fixtures. |
| Boltz's multi-process operator topology as an Immortal requirement | Immortal remains one binary and one Postgres database. Independent LPs are market participants, not required support services hidden behind the relay. |
| One provider API as the market authority | The Liquidity Market must admit independently keyed providers using participant-selected relays and policies. |
| Relay custody of LP inventory or user funds | The relay never holds balances, wallet seeds, node macaroons/NWC secrets, private claim/refund keys, or unreleased preimages. |
| Provider status as settlement truth | A signed status is evidence about a provider's claim. The wallet verifies chain, Lightning, or other rail state independently. |
| Public swap secrets and account metadata | RFQs, Quotes, Orders, invoices, addresses before funding, credentials, disputes, and recovery traffic are pairwise private by default. |
| Raw REST calls as the safety boundary | Compatibility is useful, but client verification and the NIP-MKT state machine own safety. |
| GitHub Actions or GitHub-billed conformance | Repository rule 11 requires manual or explicitly approved non-GitHub proof. |

## Follow-ups

1. Write and pin NIP-MKT plus an MKT-SWP profile with exact event kinds,
   privacy rules, signatures, idempotency, transitions, timeouts, errors, and
   fixtures. Do not extend NIP-90 for the new market.
2. Inventory every relevant official, Block, and OpenAgents NIP in the
   three-lane implementation ledger; implement the role each one actually
   defines before advertising it.
3. Build client-side script, tree, invoice, amount, fee, hash, confirmation,
   and refund verification from owned primitives or separately approved
   license-compatible components.
4. Prove one Bitcoin-to-Lightning regtest profile against at least two
   independently keyed providers and multiple relay sets, including the full
   noncooperative refund journey.
5. Add Boltz REST/WebSocket compatibility only after the native NIP-MKT path
   passes the same fixture and adversarial corpus.
