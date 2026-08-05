# Provider funded smoke

`scripts/test-provider-funded.sh` is the local, manually run gate for the
funded `immortal-provider` process. It starts one disposable provider, one
relay, separate provider and relay Postgres databases, Bitcoin Core regtest,
two Core Lightning nodes, and the Boltz hold-invoice plugin. It then requires
an external client actor to complete:

1. a submarine swap ending in a confirmed provider claim and a paid ordinary
   Lightning invoice;
2. a reverse swap ending in a confirmed client claim and a settled hold
   invoice; and
3. a reverse swap whose client does not claim, ending in the provider's
   confirmed script-path refund and a cancelled hold invoice.

The external actor is `immortal-lab funded-smoke` and uses the production
client engine for each journey. Before either participant funds, it
reconstructs the bilateral contract, binds and
parses the requester `ExitPackage`, and completes the applicable
verify-before-fund transition. In the reverse journeys, the provider may add
the exact funding transaction only after its hard reservation has durably
selected the inputs. The requester verifies that signed precommitment before
authoring `requester_lock_verified`, and the provider must broadcast those
same bytes. Each journey finishes only after the client engine accepts the
provider's signer-local terminal Close (`completed` or `refunded`).

The funded journey process succeeding is insufficient. The shell harness reads
`tests/fixtures/provider/funded-smoke-v1.json` and independently checks the
reported transaction IDs through bitcoind, verifies that each terminal
transaction spends its journey's exact lockup outpoint, checks the ordinary
and hold invoice states through the two CLN sockets, and requires the
provider's pending and unresolved watch-job metrics to return to zero without
an operator alert. It then runs a checked-in prepared query against the
private provider Postgres, binding each reported order ID to exactly one of
three distinct sessions. Every session must have its expected terminal Close
disposition, its one hard reservation must be released by `terminal_close`,
and every durable effect for that session must be `applied`, with no active,
pending, or unresolved row. The cooperative reverse refund watch must be
`completed` with disposition `claim_settled`; the noncooperative refund watch
must be `confirmed` with disposition `confirmation` at the three-block
terminal depth. Funding, claim, and reverse-lock actions stop when the current
chain height reaches their signed exclusive deadline, including the
exact-deadline boundary.

## Reusable adversarial-lab provisioning

The wider #18 topology uses `scripts/lab-bitcoind.sh`, `scripts/lab-cln.sh`,
and `scripts/lab-topology.sh`, pinned by
`tests/fixtures/lab/provisioning-v1.json`. The Bitcoin helper creates an
opt-in-RBF wallet payment with `rbf-send` and replaces it at an explicit
sat/vB fee rate with `rbf-replace`; it refuses confirmed or non-replaceable
transactions and confirms that the replacement entered the local mempool.

The CLN helper starts three isolated roles: provider-a, provider-b, and the
wallet harness. Both provider nodes must load a caller-supplied hold-plugin
executable and expose `holdinvoice`, `listholdinvoices`, `settleholdinvoice`,
and `cancelholdinvoice`; bring-up fails and removes its recorded resources if
any probe fails. The wallet node receives no provider plugin. The channel
step opens and balances both wallet spokes and the provider-to-provider edge.
This is the two-provider lab topology; the smaller funded smoke described
above continues to use its own disposable two-node Compose topology.

`scripts/lab-extensions.sh` reserves loopback allocations and an executable
hook contract for LND (#29), elementsd (#27), and arkd (#20). These entries
remain `hook-only`: the wrapper does not claim those rails are implemented.
It passes only the extension id, owning issue, non-secret run id, isolated
state directory, and port manifest. Credentials remain in the owning
process's mode-0600 state and never enter the fixture, relay, or wrapper.
Every provisioning script refuses unrecorded paths; container teardown also
requires the live container or network id to match the one created by that
run.

On macOS or Debian, the helpers select native `bitcoind`/`lightningd` from
`PATH` first and otherwise select a working Docker or Podman service. Native
CLN requires `IMMORTAL_LAB_CLN_HOLD_PLUGIN` or `hold` on `PATH`. The container
branch builds the already pinned, digest-checked CLN-plus-hold image from
`scripts/support/provider-funded/Dockerfile.cln-hold` when it is absent, and
removes that image on teardown only when the current image id still matches
the one built by the run. Then run:

```sh
scripts/lab-bitcoind.sh up
scripts/lab-cln.sh up
scripts/lab-cln.sh fund
scripts/lab-cln.sh channel
scripts/lab-topology.sh
```

Stop extensions first, if any, then run `scripts/lab-cln.sh down` before
`scripts/lab-bitcoind.sh down`. An extension owner plugs into the reserved
boundary by setting the manifest-named variable, for example
`IMMORTAL_LAB_LND_HOOK=/absolute/path/to/hook`, and invoking
`scripts/lab-extensions.sh up lnd`. An absent hook exits 2 and creates no
state.

Regtest has no fee history for a useful `estimatesmartfee` result. The harness
therefore sets `IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2` explicitly
and pins spread and routing policy so the submarine invoice amount comes from
the same pricing engine used by funded production Quotes.

## Current result

**Passed locally.** On 2026-08-04, `scripts/test-provider-funded.sh` completed
on macOS 26.4 arm64 with `test-provider-funded: submarine, reverse, and
noncooperative refund passed` after stopping the first `immortal-lab` process
at `submarine:funding_authorized` and completing with a new process restored
from the persisted engine snapshot. This records local disposable-regtest
conformance. It is not a clean-Debian installation, live-network, or
deployment claim; issue #19 owns that evidence.

## Pinned rail software

The test images support Linux `amd64` and `arm64`, including Docker Desktop on
Apple silicon and Intel macOS.

| Component | Pin | Verification source |
| --- | --- | --- |
| Bitcoin Core | 31.1 official Linux binaries | [Bitcoin Core 31.1 downloads and SHA256SUMS](https://bitcoincore.org/bin/bitcoin-core-31.1/) |
| Core Lightning | `elementsproject/lightningd:v26.06.6@sha256:094be3630f865c795649d6063a8796afa0f78e82a0c311bb34f2b0bd570c819a` | [Core Lightning v26.06.6](https://github.com/ElementsProject/lightning/releases/tag/v26.06.6) and [official Docker instructions](https://docs.corelightning.org/docs/docker-images) |
| CLN hold plugin | Boltz `v0.3.3` release assets, independently SHA-256 checked per architecture | [BoltzExchange/hold v0.3.3](https://github.com/BoltzExchange/hold/releases/tag/v0.3.3) and [command documentation](https://github.com/BoltzExchange/hold#commands) |
| Postgres | `postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193` | [Docker Official Image packaging source](https://github.com/docker-library/postgres) |

`Dockerfile.bitcoin` downloads from `bitcoincore.org` and checks the committed
31.1 archive digest before copying `bitcoind` and `bitcoin-cli` into the smoke
image. `Dockerfile.cln-hold` starts from the pinned official CLN multi-platform
image and checks the digests published on the Boltz GitHub release assets.
The harness probes `holdinvoice`, `listholdinvoices`, `settleholdinvoice`, and
`cancelholdinvoice` before funding a channel.

## Custody and isolation

Every run creates a mode-0700 directory with `mktemp`. RPC and database
passwords, the provider and client seeds, identity secrets, private
environment files, rail responses, and runtime logs are mode 0600. Each
container receives only the files its role needs. In particular, the client
driver cannot mount the provider seed, identity environment, provider
Postgres credential, or provider CLN socket. The directory, built project
images, and all named volumes are removed on success, failure, or
interruption.

The two CLN data volumes are mounted only by their owning CLN processes. Each
CLN writes `lightning-rpc` into a separate socket-only volume: the provider
receives the provider socket and the external actor receives the peer socket,
without either process receiving a CLN wallet data volume.

The CLN rail uses its native Unix JSON-RPC socket. LND is excluded from v1, so
this topology creates no macaroon. The hold plugin's optional TLS gRPC server
is disabled; the provider probes and uses only the CLN plugin commands over
the native socket. Generated preimages stay in a mode-0600 `immortal-lab`
wallet-state record and the involved CLN process; the record is removed after
terminal Close. The public evidence file contains hashes and
transaction IDs and rejects custody-field names.

The provider, relay, client driver, and alert receiver share bitcoind's
container network namespace. This preserves the provider's loopback-only
bitcoind connection and the local relay actor's loopback restriction without
bridging a Unix socket through macOS. Service data stays in separate named
volumes. The provider is funded through the normal read-only
`immortal-provider address` command and then starts as `immortal-provider run`.

## Run

Start Docker Desktop (or a Podman service with Compose support) and run:

```sh
cargo test --locked -p immortal-provider --lib provider_runtime_fixture
./scripts/export-provider-contract.sh --check
./scripts/test-provider-funded.sh
```

The first command replays the provider runtime fixture through the production
held-HTLC, deadline, hold-state, and reverse-spend/watch-retirement helpers.
The second proves that the runtime fixture digest is the one exported in the
provider contract. Both are prerequisites for the process-level gate; neither
substitutes for it.

The script has bounded readiness loops and prints only phase failures or its
final result. Build output, daemon output, rail responses, and the aggregate
Postgres evidence remain inside the private temporary directory and are
deleted during cleanup. The Postgres query returns counts, state names, and
dispositions rather than stored events or custody-bearing records. No GitHub
workflow or billed runner is involved.

The external actor is `crates/immortal-lab/src/funded.rs`, built as the
`immortal-lab` binary in the disposable driver image. The script first stops
that process at `submarine:funding_authorized`, validates its private engine
snapshot and money-safe checkpoint, then starts a new process which restores
the same session and completes all three journeys. Its only success artifact is
the private evidence set validated by the harness; a missing test, missing
artifact, unconfirmed transaction, wrong invoice state, nonterminal database
row, wrong watch disposition, or unresolved watchtower job fails the gate.

## Image preflight record

On 2026-08-04, the `arm64` Bitcoin Core and CLN-plus-hold Dockerfiles built on
macOS 26.4 through the local Apple Container BuildKit. The resulting Bitcoin
image reported `Bitcoin Core daemon version v31.1.0`; the hold binary loaded
all required shared libraries in the pinned CLN image. Shell syntax, fixture
JSON, evidence-validator Python, and Compose expansion also passed locally.
The same 2026-08-04 run completed the scripted harness restart, all three
journeys, and the aggregate durable evidence check. Future platform or release
claims require their own successful invocation; this record applies only to
the local macOS 26.4 arm64 run.

The three-node provisioning layer, mandatory hold-plugin path, native-PATH
branches, RBF replacement path, and extension hooks have static fixture
coverage through `scripts/test-lab-provisioning.sh`. On 2026-08-05 the
container Bitcoin path also created and replaced an opt-in-RBF transaction at
2 then 4 sat/vB, verified the replacement in the mempool, and removed its
recorded container, network, and state on macOS 26.4 arm64. The full topology
does not yet have a recorded clean-machine funded execution. Issue #32 remains
open until the funded smoke and checkpoint matrix are recorded on clean macOS
and Debian machines; this document makes no such claim for this packet.
