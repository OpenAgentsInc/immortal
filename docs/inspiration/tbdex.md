# tbDEX

## Source

| Field | Value |
| --- | --- |
| Repository | <https://github.com/TBD54566975/tbdex-whitepaper> |
| Local source | `~/work/projects/repos/tbdex-whitepaper/` |
| Pinned commit | `62c466774f36671ce89649b9507f6802a3b60475` |
| Version | whitepaper v0.2 |
| License | Apache-2.0 |
| Primary files | `whitepaper.tex`, `whitepaper.pdf` |
| Review date | 2026-08-04 |

The local whitepaper is the normative source for this review. Later tbDEX
protocol and SDK repositories are historical implementation context, but they
are not source inputs to this pinned record and cannot be borrowed until a
separate review pins their exact revisions and licenses. No tbDEX code is
copied by this review.

## What it is

tbDEX proposed a common negotiation protocol for wallets and many independent
liquidity providers, especially where social trust cannot be removed: fiat
on/off ramps, regulated institutions, reversible payment instruments, and
identity-dependent risk. It deliberately avoided a federation, governance
token, universal provider list, and protocol-wide KYC rule. Each wallet chose
which providers and credential issuers to trust; each provider chose what
facts, price, settlement method, and risk it would accept.

Its durable contribution is a provider-neutral market grammar. The original
ASK/BID language later became a clearer lifecycle:

```text
ProviderProfile -> Offering -> private RFQ -> signed expiring Quote
                -> signed Order -> sequenced OrderStatus -> Close
```

For OpenAgents, this is the reusable **NIP-MKT negotiated-market fabric**
beneath the Liquidity Market. Boltz supplies the strongest atomic profile;
tbDEX supplies the common language that can also describe coordinated,
federated, mint-custodial, or regulated routes without pretending their trust
models are equivalent.

## Borrow

| Item | Upstream location | How Immortal adapts it |
| --- | --- | --- |
| Common protocol for heterogeneous providers | `whitepaper.tex`, abstract and trust-model sections | Define one narrow negotiated-market envelope with rail-specific profiles. Providers compete on price, custody, finality, privacy, credentials, latency, and recourse rather than conforming to one operator model. |
| No federation or governance token | `whitepaper.tex`, trust-model section | Keep participation protocol-open and provider-neutral. Relay policy may be strict, but no Immortal deployment becomes the universal membership or ranking authority. |
| Wallet-selected provider discovery | `whitepaper.tex`, PFI Discovery | Use NIP-51 lists, NIP-65 relay choices, NIP-66 observations, NIP-87 mint/federation discovery, NIP-99 human listings, and local policy. Never publish one canonical provider rank. |
| Public discovery, private negotiation | `whitepaper.tex`, RFQ and point-to-point protocol | Replicate public profiles and Offerings; send RFQ, Quote, Order, Status, credentials, and recovery traffic pairwise using the pinned private-message NIPs. |
| Signed, expiring bids | `whitepaper.tex`, Properties of a BID | Every Quote binds provider identity, Offering/RFQ digests, exact assets and networks, amounts, fees, expiry, reservation, guarantee/custody class, evidence profile, and recourse. |
| Minimum acceptable disclosure | `whitepaper.tex`, VC and PFI sections | The wallet shortlists before presenting credentials. Presentations bind audience, purpose, RFQ/Order nonce, and expiry; reusable PII and bearer credentials never enter public relay storage. |
| Risk-priced trust | `whitepaper.tex`, PFIs and Risks sections | Make credential burden, reversibility, chargeback/default exposure, settlement delay, and legal/arbiter recourse explicit Quote fields. Do not flatten them into one reputation score. |
| Provider-independent settlement | `whitepaper.tex`, protocol-flow sections | Immortal coordinates and verifies evidence but does not execute fiat or claim finality. The wallet/provider and underlying rail remain the settlement authorities. |
| Timeout and recovery awareness | `whitepaper.tex`, on-ramp/off-ramp examples | Every profile declares cancellation, timeout, recovery, dispute, and terminal-state rules. Non-atomic routes disclose the interval in which one party is exposed. |
| Conformant protocol and wallet/provider implementations | `whitepaper.tex`, Future Development | Turn the paper's promised specification/SDK discipline into Immortal-owned NIP-MKT schemas and cross-role fixtures before runtime adoption. |

## Reject

| Item | Reason |
| --- | --- |
| DID/DWN as mandatory identity and transport | Nostr keys, signed events, participant-selected relays, and pinned NIPs are Immortal's protocol substrate. Add selective credential interop only where a provider genuinely requires it. |
| Archived tbDEX SDK as a critical dependency | The project is no longer maintained, and Immortal must own its Rust primitives under the repository dependency and licensing rules. |
| A universal provider directory or global score | It creates a new central trust authority and is vulnerable to capture and Sybil manipulation. Wallets choose lists, issuers, monitors, and policies. |
| Public broadcast of financial RFQs or credentials | It leaks amounts, intent, account data, and identity material and enables harvesting and front-running. |
| Calling every route trustless or atomic | Fiat, mint, federation, escrow, and custodian routes retain distinct failure and recourse models. The protocol must expose rather than erase them. |
| Relay authority over payment finality | `OK`, storage, Status, or Close proves protocol behavior, not settlement. Verify the underlying rail. |
| Custody inside Immortal | Funds, balances, spend keys, bank credentials, node secrets, unreleased preimages, and private refund/claim keys stay outside the relay. |
| One enormous market NIP | Negotiation can share a small spine; swaps, P2P, PFI, mint/federation, LSP, labor, data, compute, and risk require focused profiles and separate invariants. |

## Follow-ups

1. Draft NIP-MKT with ProviderProfile, Offering, RFQ, Quote, Order, Status,
   Close, cancellation, idempotency, privacy, error, reservation, and evidence
   laws.
2. Draft focused MKT-SWP, MKT-P2P, MKT-PFI, MKT-MINT, and MKT-LSP profiles;
   add MKT-RISK only when a real guarantee, underwriter, and claims authority
   exist.
3. Map the complete pinned official, Block, and OpenAgents lanes to relay,
   client, operator, provider, and executor roles. Reuse exact existing NIPs
   instead of duplicating their semantics.
4. Build a transport-neutral native/browser wallet router that discovers from
   multiple relays, shortlists locally, negotiates privately, persists before
   publish, and verifies rail evidence independently.
5. Prove a two-provider atomic corridor first; then add P2P, mint/federation,
   LSP, and credentialed PFI routes with their custody and failure journeys
   visible in every Quote.
