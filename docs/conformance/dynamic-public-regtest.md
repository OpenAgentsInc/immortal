# Dynamic public-regtest sessions

Issue #43 replaces the fixed-amount demo journey with a closed, bounded
request contract and a live two-provider proof. It supports only Bitcoin
regtest submarine and reverse swaps.

## Request and commitment

`openagents.immortal.dynamic-public-regtest-request.v1` accepts 10,000 through
1,000,000 sat, a fee ceiling below both 50,000 sat and the input, and a request
lifetime of at most ten minutes. Reverse requests require a valid `bcrt1`
SegWit destination. Submarine requests require a signed, amount-bearing,
unexpired `lnbcrt` BOLT11 invoice with whole-satoshi value and no unknown
required feature bit.

Parsing is duplicate-member rejecting and closed to unknown fields. Typed
refusals distinguish framing/schema, network, amount, fee, expiry,
destination, invoice amount, and feature failures. The public projection
contains the destination kind and SHA-256 commitment, never the address or
invoice. Each requester-signed RFQ carries that same commitment: the invoice
bytes for submarine, or the exact executed scriptPubKey for reverse. Signed
Quote, Order, and bilateral Contract causality makes later mutation a new,
unauthorized session.

Public visitors who do not operate a regtest wallet may first request a
single-use demo input through the capability gateway. The generated address or
invoice is then processed by this unchanged strict request contract, so the
convenience allocator does not bypass network, amount, expiry, destination, or
input-to-effect binding.

The OpenAgents browser package remains the host-side UI precheck. Immortal
independently parses and verifies the signed execution inputs in Rust because
a TypeScript-only validator cannot be funding authority. No new browser ABI
operation is required: the existing typed RFQ, Order, Contract, session
create/restore/ingest, exit-package, prepare-funding, and verify-before-fund
operations already carry dynamic JSON and exact signed bytes. ABI v1 and its
operation inventory therefore remain unchanged.

## Selection and execution

Both separately keyed funded providers receive the same request and return
hard Quotes before either Order exists. Candidates must agree on direction,
assets, input, arithmetic, and rounding. Ordering is deterministic:

1. greatest output;
2. lowest maximum total fee;
3. provider public key;
4. Quote ID.

The losing provider is ordered only to prove the complete reservation path,
then receives signed accepted/effective cancellation and a truthful
`cancelled` Close. Its terminal accounting requires zero external effects,
zero committed input, and exact reservation release. Reverse
`hold_invoice_ready` is explicitly a cancellable pre-effect state; cancelling
it also confirms cancellation of the provider hold invoice.

Only the winner crosses verify-before-fund. Submarine executes a real Bitcoin
funding/claim and pays the entered invoice. Reverse executes the real hold
invoice/funding/claim sequence and pays the exact entered scriptPubKey. Its
public result separates the quoted contract output from the net destination
amount after the bounded claim fee. Terminal presentation is emitted only
after requester-admitted Bitcoin and Lightning evidence and a verified Close.

## Verification

Run:

```sh
scripts/test-dynamic-funded-topology.sh
scripts/test-client-browser-abi.sh
```

The first command builds a disposable two-relay, two-provider, two-provider-
database, bitcoind, and three-CLN topology. It executes both directions,
retains only a custody-free normalized result, checks deterministic selection,
loser release, exact destination/invoice settlement, and terminal evidence,
then removes all private state. The fixture is
`tests/fixtures/lab/dynamic-public-regtest-v1.json`.

The compiled zero-import WASM gate exercises the unchanged production browser
ABI's dynamic-capable session operations and typed mutation refusal. Existing
requester/provider restart matrices prove exact snapshot restore, receipt
replay, no duplicate rail effect, refund, and timeout semantics used by these
sessions; the dynamic process gate uses those same production engines rather
than a parallel session implementation.

This is not a public deployment claim. Mainnet, testnet, signet, Liquid,
BOLT12, LNURL, arbitrary extensions, and browser custody remain unavailable.
Shared-service load, remote TLS, retention, and operator acceptance belong to
issue #44.
