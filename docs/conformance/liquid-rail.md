# Liquid rail conformance

Issue #27 adopts the MKT-SWP Liquid addendum pinned in `nips/manifest.json`.
The rail is optional and disabled unless the provider receives one complete,
valid elementsd configuration. It allocates no event kind and changes no relay
storage, gateway behavior, or NIP-11 advertisement.

## Authority boundary

Immortal parses the bounded Elements transaction envelope, binds the exact
selected output and its serialized commitments, re-derives the Taproot script
tree and unilateral exit, and submits completed spends to the configured
node's consensus and mempool policy. For a confidential output, the
participant must obtain the asset and amount from its own local wallet. The
recorded authority is `local_elementsd_unblind`.

The implementation does not independently verify an arbitrary third party's
range proof or surjection proof. Successful local unblinding does not upgrade
the node or wallet into an independent confidential-proof authority. V1
admits only the exact `pegged_asset` returned by the configured Elements
network.

No seed, spend key, claim key, refund key, blinding key, value blinder, asset
blinder, RPC password, or unreleased preimage may enter a Swap Contract,
provider Postgres, relay record, retained lab record, or conformance output.

## Executable layers

The fixture-first proof is split into four layers:

1. `crates/immortal-core` replays bounded transaction, asset, commitment,
   script, and parser mutations from `liquid-rail-v1.json`.
2. `crates/immortal-client` binds the Liquid request to bilateral Swap
   Contracts and the exact local genesis, persists a secret-free unilateral
   exit before authorization, emits typed external effects, and restores the
   same decision after restart. Presigned refunds contain no custody material;
   hashlock claims use `wallet_sign` plus a non-secret recovery reference and
   obtain the preimage only through the local execution callback. Presigned
   recovery emits a typed local-elementsd broadcast request immediately; a
   wallet claim emits the same request only after its returned witness verifies.
   Both bind the full genesis, signed-transaction digest, and opaque private
   artifact reference. The executor reloads and digest-checks the exact bytes;
   the typed recorder derives the transaction ID from those bytes, while the
   generic effect recorder refuses Liquid broadcasts. A crash after node
   acceptance reloads the retained artifact without re-signing or overwriting
   it. The client snapshot retains no claim witness or preimage. Only recording
   the broadcast—not wallet signing—suppresses a second execution after restore. In a
   BTC→L-BTC chain it requires local elementsd mempool acceptance of the exact
   signed, unbroadcast Liquid destination template while it verifies the
   Bitcoin source; reverse swaps still require confirmed Liquid lock finality.
   Both chain destination templates are verified before the provider may emit
   `source_funding_required`. Terminal Close verification binds Liquid output
   and spend evidence to the exact contracted outpoint. A destination that was
   never funded uses the exact released reservation plus verified absence of a
   destination funding effect; source evidence cannot be reused for that leg.
   The recovery schema accepts the optional complete `taproot_tree` only when it
   matches the bilateral verifier and rejects every unknown member.
3. `crates/immortal-provider` connects the optional rail to funded quoting,
   hard reservation, exact-byte funding and exit effects, observation,
   conflict/reorg handling, and durable restart recovery. Mixed-chain timeout
   heights are derived per rail from one safe wall-clock ladder, so neither
   orientation permits the source refund before the destination recovery
   margin. The fixture-pinned Liquid weights are 1,700 vbytes for one-input
   confidential funding and 300 vbytes for either unilateral exit. The signed
   total fee budget covers the provider's worst-case effect set for that swap
   orientation and derives one exact sat/vbyte rate; each provider effect
   receives only its weight-proportional share. A requester-authored Liquid
   source uses the same derived rate and the 1,700-vbyte funding cap without
   adding that separately paid transaction to the provider's quoted costs;
   its claim or refund similarly uses only the 300-vbyte exit share. A
   provider-funded Liquid reservation is therefore one confirmed
   participant-owned output that alone covers the swap amount plus the full
   signed fee budget. This admission bound is conservative: the funding effect
   may spend only its weight-proportional share. Split capacity fails closed
   instead of adding an unpriced input. Funding must spend exactly the reserved
   input and its node-reported
   fee must match one explicit fee output under the signed maximum. Exact already-known
   transactions are admitted only after fetching and comparing their raw
   bytes. Funding and unilateral-exit effects persist the complete public
   request before rail I/O; an applied effect replays after a Postgres
   reconnect without another RPC, while changed funding context or exit bytes
   conflict. A crash after broadcast but before Status publication rehydrates
   that request without requiring an unspent output or another signature.
   Final claim and refund observations are checked again through terminal
   Close, with a finality regression entering `unresolved`.
   Elements Core 23.3.3 does not expose Bitcoin Core's
   `gettxspendingprevout` RPC. The adapter instead scans at most 4,096 mempool
   transactions and 144 recent decoded blocks for an exact input outpoint,
   rejecting oversized inputs, blocks, and multiple spenders. If that bounded
   scan finds no spender, `gettxout` must still report the contracted output;
   a missing output fails loudly as a spend outside the retained scan window
   instead of being treated as unspent.
   Elements Core 23.3.3 omits `confirmations` for an unconfirmed verbose
   transaction; the adapter normalizes that omission to zero only when no
   block hash exists. It accepts only `(0, no block hash)` as mempool state and
   `(positive, exact block hash)` as confirmed state.
4. The disposable lab runs Liquid submarine, Liquid reverse, BTC→L-BTC, and
   L-BTC→BTC sessions against provider A and provider B with separate provider
   state and Elements wallets. It also removes the provider for a presigned
   Liquid submarine refund and removes both relays plus the coordination path
   for direct Liquid reverse recovery. The process proof retains only signed
   public identifiers, transaction identifiers, output indices, state names,
   digests, and boolean checks.

The local commands are:

```sh
cargo test --locked -p immortal-core --test mkt_swp_profile
cargo test --locked -p immortal-client --test liquid
cargo test --locked -p immortal-provider --test provider_liquid
scripts/test-provider-liquid.sh
scripts/test-lab-adversarial.sh --all
scripts/export-contract.sh --check
scripts/export-provider-contract.sh --check
```

## Taproot signing source and scope

The Elements script-path implementation is an in-repository adaptation of
the following pinned sources:

- Elements Core
  `7110a84bb1feafcb32a611a3e75135e7375495c1`,
  `doc/taproot-sighash.mediawiki` (MIT);
- go-elements v0.5.5, `transaction/transaction.go`,
  `taproot/taproot.go`, and `transaction/data/tx_valid.json` (MIT);
- boltz-core `a932d49c4daaeae3d7940dc1519bf77ef92e6dc1`,
  `lib/liquid/swap/TaprootUtils.ts` and `lib/liquid/swap/Claim.ts`
  (MIT); and
- boltz-client `746f73c5ecbd3621f628f60108a404ef26f0de95`,
  `pkg/boltz/liquid.go` (MIT).

No source code was copied. The implementation reproduces the documented
consensus serialization with the Elements `TapLeaf/elements`,
`TapBranch/elements`, `TapTweak/elements`, and `TapSighash/elements` tags and
leaf version `0xc4`. The claim and refund fixture hashes and signatures were
produced independently with go-elements v0.5.5, then replayed by
`immortal-core`. Negative vectors change the annex, revealed script, control
block, input, output, prevout asset, and prevout value.

The public core API supports `SIGHASH_DEFAULT` script-path signing and
verification, including an optional consensus annex. It retains and commits
to exact issuance fields, issuance proofs, output commitments, and output
proofs. It does not implement key-path signing, non-default sighash modes, or
arbitrary tapscript execution. Callers must separately validate the admitted
claim or refund script shape and pass its expected signing key. Confidential
proof verification remains delegated to the participant's local Elements
wallet as described above.

The wrapper owns every temporary elementsd container, image, state directory,
credential, and host port. Success requires ownership-checked cleanup to zero;
a failed teardown retains the exact recovery record and fails the gate.

The `regtest_adversarial` profile pins quote pricing to its explicitly
configured fallback feerate and refuses startup without one. It does not use a
live `estimatesmartfee` result, so the requester can derive its submarine
invoice and transaction caps from the same fixture-pinned observation. This
lab-only override leaves production's live-estimate-first policy unchanged.

The adversarial runner observes and validates each provider-originated
transaction on the node that will mine the next block before requesting that
block. A signed provider Status is not evidence that peer-to-peer propagation
has completed. The wait is bounded and fails closed; the runner never mines a
replacement transaction or fabricates a node observation after a timeout.
The requester retains the production verifier's opaque pre-fund authorization
through the claim broadcast. It does not rerun a mempool-only preflight after
the funding transaction has confirmed or reconstruct an authorization from
the retained transaction bytes.

## Claim boundary

A green local record establishes executable Liquid rail conformance for the
tested configuration. It does not establish live deployment, operator
independence, public liquidity, production finality, or a public Boltz
replacement claim. Those claims require their own deployment evidence.

The complete 43-case process gate passed from pushed `main` `6c4cd10` on
2026-08-06. Its 247,375-byte aggregate remains below the fixture-pinned
262,144-byte limit and is retained as
[`records/2026-08-06-adversarial-regtest-6c4cd10.json`](records/2026-08-06-adversarial-regtest-6c4cd10.json).
The record keeps `live_deployment`, `independent_operator_deployment`, and
`public_replacement` false.
