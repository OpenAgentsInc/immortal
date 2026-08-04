# Satora / LendaSwap ecosystem

## Source

| Field | Value |
| --- | --- |
| Organization | <https://github.com/satoraHQ> ("Make Bitcoin Move") |
| Local review set | `~/work/projects/satora/repos/` (25 public repositories) |
| `lendaswap-contracts` | `28c6224` (MIT) |
| `satora-sdk` | `ff56114` (MIT) |
| `lendaswap-frontend` | `f0c020c` (MIT) |
| `arkade-ts-sdk` | `52dba83` (MIT) |
| `wdk-protocol-bridge-satora-bitcoin` | `af9d2a6` (Apache-2.0) |
| `striker` | `191ddce` (no license file) |
| `doomsday` | `b035a4f` (no license file) |
| `lendasat-sdk` | `cfc813c` (no license file) |
| `regtest-devenv` | `3a0e6af` (no license file) |
| Review date | 2026-08-04 |

The repositories without a license file are ideas-only reference: no code,
fixture data, or configuration is copied from them. The MIT and Apache
repositories may donate license-compatible material with source, commit,
path, and license recorded per this directory's rules. No Satora code is
copied by this review. The full teardown lives in the OpenAgents monorepo at
`docs/teardowns/2026-08-04-satora-lendaswap-outage-teardown.md`.

## What it is

Satora (formerly Lendasat/LendaSwap) runs non-custodial atomic swaps between
Bitcoin — on-chain, Lightning, or Arkade (Ark VTXOs) — and EVM tokens on
Polygon, Ethereum, and Arbitrum, over SHA-256 HTLCs on both legs, with client
SDKs holding keys and preimages and a closed-source company coordinator
(`api.satora.io`) doing quotes, pairing, and liquidity. On 2026-08-04, during
this review, the coordinator returned 502 while every static surface stayed
up — the second swap coordinator outage in days after Boltz, and the same
shape: settlement physics intact, one-company coordination layer dark.

## Borrow

| Item | Upstream location | How we adapt it |
| --- | --- | --- |
| EVM-HTLC leg design | `lendaswap-contracts` (MIT): `HTLCErc20`, `HTLCCoordinator` | The BTC↔EVM pair vocabulary for a future MKT-SWP-EVM extension: SHA-256 preimage compatibility across legs, claim-address binding against front-running, hash-verified minimal storage, gasless EIP-712 redeem/refund. Reference shapes for the extension's evidence verifier; reimplemented, never linked |
| Gasless-claim term | `HTLCErc20` EIP-712 flows | Who pays destination-chain execution is a disclosed quote field in the EVM extension, not a provider default |
| Confirmation policy as a quoted term | `satora-sdk` `ff56114` (EVM→BTC claims moved to 0-conf the day before the outage) | Confirms the MKT law: confirmation/RBF policy is a taker-visible quoted term with provenance labels; fixture the negative case |
| Doomsday recovery law | `doomsday` (ideas only) | The doomsday drill: every executable profile proves both parties reach the correct terminal state with the coordinator permanently gone, from persisted signed records plus the counterparty channel. Their use of Nostr-derived npubs as the recovery rendezvous independently validates the fabric choice. Lands as named acceptance cases in the client swap engine (#12) and adversarial lab (#18) |
| Covenant-enforced reservation | `striker` DESIGN/README (ideas only) | A covenant-guaranteed reserve is a rail-proof class for a `hard` reservation — stronger than a signed claim. Feed into the coordination handlers (#13) and the SWP draft vocabulary (openagents#9311). Also record their anti-pattern: an orderbook of on-chain outputs welds price to output and makes every requote a chain action |
| Regtest environment shape | `regtest-devenv` (ideas only) | Service topology reference for the adversarial lab (#18): bitcoin regtest + electrs, LND + CLN, arkd + wallet, swap components beside the relay — external nodes never enter this binary or its allowlist |
| Ark escrow constructions | `ark-lightning-escrow-sample`, `arkade-lightning-2of{2,3}-escrow` | Coordinated hold/escrow (custody class A1) primitives on the Ark rail for a later profile |
| Distribution interfaces | `btcpayserver-satora-plugin`, `iframe`, `wdk-protocol-bridge-satora-bitcoin` (Apache) | The three adoption surfaces (merchant plugin, embed widget, WDK swidge provider) a multi-provider Immortal network can serve through the generated SDK and the Boltz-compatible facade (#15) |
| Nostr identity in product | `lendasat-sdk` `Wallet::npub`; doomsday npub rendezvous | Precedent: the wallet's Nostr key is the durable market identity, not an account at a coordinator |

## Reject

| Item | Reason |
| --- | --- |
| Company-coordinator architecture | Closed-source backend in a private registry behind one API host is the exact single point of failure NIP-MKT replaces with public discovery, wrapped negotiation, and many providers |
| Unlicensed repos as code donors | `striker`, `doomsday`, `lendasat-sdk`, `regtest-devenv`, `arkade-wallet` carry no license file — laws and ideas only |
| DEX composition on the critical path | `executeAndCreate` arbitrary-call composition widens taker verification obligations; if ever admitted it is a separately disclosed and verified term |
| Account-model semantics in the relay | Gas sponsorship, permits, and EVM addresses live in profile adapters and wallets; the relay validates events, never chain state |
| Backend liquidity model | Provider-of-record liquidity stays with independent providers; Immortal coordinates and never quotes, holds, or fills |

## Follow-ups

1. openagents#9311: reserve the EVM-leg vocabulary in the MKT-SWP draft
   (chain id, contract, token, signature mode, confirmation policy) so an
   MKT-SWP-EVM extension lands without a breaking revision.
2. #12/#18: add the doomsday drill as a named acceptance case (coordinator
   permanently gone; counterparty-only completion).
3. #13: admit covenant-enforced reserves as a `hard`-reservation proof
   class in the reservation vocabulary.
4. #18: use the regtest-devenv topology as the lab's external-node
   reference; add the EVM leg when the extension exists.
5. Owner question: pull the `arkade-os` org (`arkd`, protocol docs) as a
   reference lane — the satora lane has Arkade clients but not the server
   implementation the escrow samples speak to.
