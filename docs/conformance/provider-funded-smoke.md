# Provider funded smoke

`scripts/test-provider-funded.sh` is the local, manually run gate for the
funded `immortal-provider` process. It starts one disposable provider, one
relay, separate provider and relay Postgres databases, Bitcoin Core regtest,
and a wallet-side Core Lightning node. The default provider rail is a second
CLN node with the Boltz hold-invoice plugin. Setting
`IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd` instead builds the provider with
its optional rustls feature and starts a pinned LND provider rail with native
hold invoices. Both variants require an external client actor to complete:

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

After all three native journeys, the harness publishes the provider's
compatibility listener through a random host-loopback port and runs the
checked-in adapted Go and browser/Node processes against the same daemon and
signed sessions. Their 13-call and 15-call subsets cover the exact 19-call
union. The submarine adapter replays prepare, bilateral finalize with its
persisted script-path exit, unchanged-byte idempotent broadcast, and an
unbound-broadcast refusal. The reverse adapter replays the public script-path
claim through the session-bound broadcast route. Status, released-secret,
transaction, rail-read, reverse-BIP21, and direct WebSocket routes are also
exercised. The in-process corpus separately proves that a same-txid witness
mutation is not an idempotent replay and that signed `created_at` skew cannot
reorder dense signer streams. Neither client process mounts provider
credentials, wallet state, or Postgres.

The Go adapter's atomically renamed control files coordinate polling with the
driver only. Their writes are not durability or custody evidence, so an
`ENOTTY` VirtioFS file sync is accepted only for that handoff. Provider
Postgres, chain, and Lightning evidence remain authoritative.

**Compatibility process passed locally.** On 2026-08-05 on macOS 26.4
arm64, the adapted Go client executed and passed its 13-call subset, and the
adapted browser/Node client executed and passed its 15-call subset with zero
skips. The fixture-pinned union was 19/19 dependent calls. The same run then
reported `test-provider-funded: submarine, reverse, and noncooperative refund
passed`. The submarine session used a `wallet_sign` exit package: both clients
matched its mode and SHA-256 to their persisted snapshot before broadcast, and
the provider returned that exact mode without implying a keyless `presigned`
package. #12's pre-signed doomsday cases remain separate coverage.

For the disposable shared Bitcoin/provider network namespace, the script reads
the runtime private IPv4 address after startup and configures the listener on
that numeric private address. Docker publishes port 19093 through a random
host port bound to loopback by default. It first probes that listener from the
shared container namespace, then resolves the published endpoint for the
caller-side Go and Node process gates. This preserves the provider's
private-or-loopback bind law while making the process endpoint reachable
through container port translation. The remote-Docker exception is bounded
below.

The funded journey process succeeding is insufficient. The shell harness reads
`tests/fixtures/provider/funded-smoke-v1.json` and independently checks the
reported transaction IDs through bitcoind, verifies that each terminal
transaction spends its journey's exact lockup outpoint, checks the ordinary
and hold invoice states through the selected provider rail and wallet CLN
socket, and requires the
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

The LND provider is a legal #18 participant through the built-in funded-smoke
variant above; it does not require an external rail hook.
`scripts/lab-extensions.sh` continues to reserve loopback allocations and
executable hook contracts for elementsd (#27) and arkd (#20). Those entries
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
boundary by setting the manifest-named variable and invoking
`scripts/lab-extensions.sh up <extension>`. An absent hook exits 2 and creates
no state.

The reusable negotiation process gate owns that bring-up and teardown in one
command:

```sh
scripts/test-lab-topology-quotes.sh
```

It requires the balanced provider-a/provider-b/wallet CLN graph, starts two
relay processes and two independently keyed production no-spend provider
actors, then uses one wallet identity to discover and request a Quote through
each relay. The wallet reconstructs each `RequesterSessionView` from its
locally signed RFQ and exact gift-wrap delivery. Candidates must be fresh,
firm, reserved, and economically comparable. Selection is total and
fixture-pinned: highest output, lowest maximum total fee, provider pubkey,
then Quote ID. The first two terms express the economic preference; the final
two make equal Quotes independent of relay or arrival order.

Private roots contain the throwaway provider and wallet signing material,
exact wraps, and process logs and are removed by identity-checked teardown.
The retained mode-0600 record contains only platform data, public CLN node
IDs and channel counts, the wallet pubkey, normalized public Quote terms, and
the selection. Its recursive allowlist excludes credentials, custody fields,
and raw signed or wrap events. This gate proves discovery and negotiation; its
providers run `--no-spend`. The separate funded topology gate below exercises
the provider CLN nodes and durable databases.

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

The combined checkpoint-recovery packet repeated that same process gate on
macOS 26.4 arm64 on 2026-08-05. The first run exposed that Bitcoin Core sends
JSON-RPC error `-5` in a bounded HTTP 500 response; the rail client now decodes
that response before the recovery policy decides whether a first broadcast is
safe. The next run caught a custody-name tripwire on boolean terminal metadata;
the fixture now records `lightning_payment_succeeded=false` without placing a
custody-bearing member name in the checkpoint. After both fixes, the forced
replacement run completed all three journeys and the independent durable
evidence checks. This remains local-machine evidence, not the clean macOS or
Debian execution required to close #32.

The LND rail gate also passed on macOS 26.4 arm64 on 2026-08-05 with
`IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd
scripts/test-provider-funded.sh`. The pinned LND process completed the same
submarine, reverse, and noncooperative-refund journeys, including restart and
durable-effect checks, and the harness removed its private credential and
state directory after teardown. This makes LND eligible for a #18 provider
slot under the feature-gated local-lab profile. It does not supply the clean
host or live deployment evidence owned by #32 and #19.

The audited `scripts/run-debian-provider-funded.sh` gate passed on a fresh
Debian 13 aarch64 disposable container on 2026-08-05 at commit
`c787a96b7b052684bf2205c6d3feee454c6fe232`. Its bounded receipt is
`docs/conformance/records/2026-08-05-funded-smoke-debian.json`: all three
funded journeys, the forced requester replacement, and the Go/web adapter
checks passed; matching provider containers and private runtime artifacts were
absent afterward. This is clean-Debian single-provider smoke evidence. It does
not prove #18's independent two-bitcoind topology, a live deployment, or a
public replacement claim.

After the remote-Docker private-root preflight landed, the same gate passed
again at commit `b066c31985d31543875d4609eb8fa90a7cf58925`. The additive
receipt is
`docs/conformance/records/2026-08-05-funded-smoke-debian-private-root-v2.json`.
It binds the current harness digest to a fresh Debian 13 process and Docker
daemon, all three journeys, the forced requester replacement, and verified
zero private-runtime retention.

The current remote-Docker process-gate harness passed the Debian gate at
commit `bd5d94ff79cacef21e261d13d487daf2c08b9315`. Its additive receipt is
`docs/conformance/records/2026-08-05-funded-smoke-debian-remote-boltz-v3.json`.
It covers the internal and caller-visible Boltz readiness checks, both adapted
client process gates, all funded journeys, forced replacement, and cleanup.

## Pinned rail software

The test images support Linux `amd64` and `arm64`, including Docker Desktop on
Apple silicon and Intel macOS.

| Component | Pin | Verification source |
| --- | --- | --- |
| Bitcoin Core | 31.1 official Linux binaries | [Bitcoin Core 31.1 downloads and SHA256SUMS](https://bitcoincore.org/bin/bitcoin-core-31.1/) |
| Core Lightning | `elementsproject/lightningd:v26.06.6@sha256:094be3630f865c795649d6063a8796afa0f78e82a0c311bb34f2b0bd570c819a` | [Core Lightning v26.06.6](https://github.com/ElementsProject/lightning/releases/tag/v26.06.6) and [official Docker instructions](https://docs.corelightning.org/docs/docker-images) |
| CLN hold plugin | Boltz `v0.3.3` release assets, independently SHA-256 checked per architecture | [BoltzExchange/hold v0.3.3](https://github.com/BoltzExchange/hold/releases/tag/v0.3.3) and [command documentation](https://github.com/BoltzExchange/hold#commands) |
| LND | `lightninglabs/lnd:v0.20.1-beta@sha256:f0a2bdc4b8bc89cb3b31b6e12d6b16ac5145defd916d8152cf0c1c07d8697cff` | [LND v0.20.1-beta](https://github.com/lightningnetwork/lnd/releases/tag/v0.20.1-beta) and the official Lightning Labs image |
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

### Remote Docker private-root parent

`IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT` optionally selects the parent
for that one private directory. It must be an existing, writable, searchable
absolute path outside the checkout and any Debian receipt directory. The
harness canonicalizes it, creates one mode-0700
`immortal-provider-funded.*` child beneath it, verifies physical containment,
then unsets the setting before it starts the smoke.

For a remote Docker daemon, this parent must be mounted at the same absolute
path on the caller and the daemon host. Set this one variable to that shared
path; do not point global `TMPDIR` at the shared mount. Docker and Buildx keep
using the caller's normal `TMPDIR`, avoiding shared-filesystem temporary-file
semantics. Before any credentials are generated, the harness bind-mounts the
empty child read-only into the pinned Postgres 17 image. A remote daemon that
cannot see the exact path fails at that preflight.

The Boltz listener publishes on `127.0.0.1` by default. If the Docker daemon
is remote and the caller must run the checked-in Go and Node process gates,
set `IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST` to the daemon's reachable
host-only private IPv4 address, for example `192.168.65.1`. The harness
accepts only loopback or RFC1918 IPv4 addresses, rejects wildcard and global
addresses before creating credentials, and requires `compose port` to report
that exact host before it runs either adapter. This is an explicit test-only
publish decision; it never changes the provider listener's private bind.

The two CLN data volumes are mounted only by their owning CLN processes. Each
CLN writes `lightning-rpc` into a separate socket-only volume: the provider
receives the provider socket and the external actor receives the peer socket,
without either process receiving a CLN wallet data volume.

The CLN rail uses its native Unix JSON-RPC socket, with the hold plugin's
optional TLS gRPC server disabled. The LND variant copies its self-signed TLS
certificate and separate readonly, invoices, and router macaroons into a
mode-0700 directory, mounts each exact mode-0600 file read-only into the
provider, and never exposes the admin macaroon. Generated preimages stay in a mode-0600 `immortal-lab`
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
IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd ./scripts/test-provider-funded.sh
```

The disposable Debian 13 process gate copies an exact committed tree into a
fresh Debian environment, installs the build, Docker, curl, Go, and Node tools
used by the funded smoke and its checked-in client adapters. Debian 13's Node
20 runs the browser-adapter probe with its built-in WebSocket explicitly
enabled through `--experimental-websocket`. The gate writes a
bounded public receipt only after cleanup. It refuses any worktree changes,
including untracked source files, and refuses to overwrite a record:

```sh
scripts/run-debian-provider-funded.sh \
  --receipt docs/conformance/records/YYYY-MM-DD-funded-smoke-debian-unique.json
```

The caller supplies Docker only to start a privileged Debian 13 container. The
gate starts a new Docker daemon with an empty data root inside that container,
then removes the entire container after the smoke. Its host-mounted receipt
directory is not the process `TMPDIR`: private runtime state stays in the
outer container and disappears with it; the funded-smoke process checks those
physical paths before it writes private state. The raw outer console is held
only in a separate mode-0700 controller directory. On failure or interruption,
the wrapper recovers its exact container ID from Docker's cidfile, removes that
container and any result, deletes the raw controller log, and retains only a
mode-0600 `failure.log` capped at the first 64 KiB and 200 lines. It retains no
private runtime directory or result. After the exact container and controller
cleanup succeeds, the result is staged beside its final path. It then ignores
termination signals and atomically publishes the final receipt as its last
mutation. The receipt records that container boundary instead of describing it
as an independent VM or live deployment.

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
has separate local records below. Issue #32 requires one exact 20-case matrix
run plus the single-provider funded restart smoke on clean macOS and Debian
hosts. The matrix is not required to repeat on both clean hosts.

## Recovery and failure-control contract

The fixture `tests/fixtures/lab/funded-checkpoints-v1.json` is the executable
manifest for replacement-process drills. It pins every accepted restart label
for submarine, reverse claim, and reverse refund journeys. The wallet driver
persists the custody-free client snapshot before each label and restores the
requester Status cursor from signed records, so replaying a step cannot create
a second sequence-zero stream. Each journey has its own checkpoint record;
`funded-checkpoint.json` is only the latest-control pointer, so completing a
later journey cannot hide an earlier journey's terminal or recovery state.

Bitcoin execution uses a durable `funding_execution_ready` or
`claim_broadcast_ready` intent bound to the transaction ID. Recovery calls
`getrawtransaction` first. Exact observed bytes continue without another
`sendrawtransaction`; JSON-RPC `-5` is the only result that permits the first
broadcast; transport and other RPC errors remain ambiguous and fail closed.
An effect-recorded or broadcast-recorded checkpoint requires the transaction
to be observable and never enters the broadcast path. Lightning recovery
queries `listpays` by the exact invoice and payment hash. Zero matching entries
permit one `pay`; one is observed to terminal state without another `pay`; two
or more fail closed. The restored client snapshot independently revalidates
the exact typed effect request/result binding.

The same fixture pins the deterministic injection vocabulary. Stale Quote,
duplicate delivery, conflicting bytes, and custody-member leakage are
harness-owned pre-fund cases. Relay loss and provider crash use a bounded
request/acknowledgement handshake at a safe checkpoint, allowing a script to
control the external process without giving the harness daemon credentials or
process-discovery authority. Checkpoints, requests, and acknowledgements reject
custody material recursively.

This packet is a harness/unit conformance record until the expanded checkpoint
and failure matrix is run through the disposable funded topology. The existing
2026-08-04 process record proves only the
`submarine:funding_authorized` replacement drill.

## Manual funded process matrix

`tests/fixtures/lab/funded-matrix-v1.json` closes the orchestration gap between
the checkpoint contract and the disposable smoke. It requires one case for
every restartable label and one case for every bounded injection in
`funded-checkpoints-v1.json`. List or run cases explicitly:

```sh
scripts/test-provider-funded-matrix.sh --list
scripts/test-provider-funded-matrix.sh --case restart-submarine-funding_effect_recorded
scripts/test-provider-funded-matrix.sh --case injection-relay-loss
scripts/test-provider-funded-matrix.sh --all
```

Each selected case invokes `scripts/test-provider-funded.sh` from an empty
mode-0700 private root, so Bitcoin, Lightning, relay, provider, Postgres,
wallet, logs, and evidence are never reused between cases. Cleanup retains the
smoke's identity-checked Compose project and temporary-directory guards on
success, refusal, failure, or interruption.

Restart cases stop the wallet process at the selected manifest label, verify
the exact safe checkpoint and journey snapshot, and replace the process before
running the independent chain, Lightning, metrics, and prepared-Postgres
evidence checks. Harness-owned injection cases either finish with no duplicate
logical record or produce their fixture-pinned refusal while the Bitcoin
mempool, provider payment list, and funded-checkpoint surface remain empty.
Relay loss and provider crash are driven only after the harness writes its
bounded mode-0600 request. The smoke stops or kills the named disposable
process, restores its health, then writes an atomic mode-0600 acknowledgement
whose run id, checkpoint, injection, and restored state exactly match the
request.

The acknowledgement is also a wallet transport boundary. Relay loss replaces
and NIP-42 authenticates the requester's reader and publisher sockets, then
resubscribes without discarding stored history; signed-record replay remains
the idempotency authority. Provider crash retains the authenticated wallet
sockets and waits for the restarted provider through the same subscription.
The provider restores an exact durable terminal reservation release before it
ingests the matching provider-authored Close; a missing or conflicting release
halts recovery.

### 2026-08-05 local process record

The complete matrix passed on macOS 26.4 arm64 with Docker Engine 29.4.3 and
Docker Compose 5.1.4. The exact-count runner executed all 20 fixture rows: 14
restart checkpoints and six bounded injections. Every restart and the
duplicate-message, relay-loss, and provider-crash cases completed submarine,
reverse claim, and noncooperative reverse refund with the independent
chain/Lightning/Postgres evidence checks. Stale Quote, conflicting message,
and secret leakage were rejected before swap-rail effects. The provider-crash
case killed and restarted the provider at
`reverse:funding_effect_recorded`; durable terminal reservation release was
restored before signed Close replay. Each case used a fresh disposable
topology, and the run-specific Compose projects and mode-0700 temporary roots
were absent after completion.

The rebased requester-API and Status-hardening tree repeated the exact 20-case
run at commit `433bfcb478e84ed9672bc3647dd680ba6a3f7dbe`. Its bounded receipt is
`docs/conformance/records/2026-08-05-funded-matrix-macos-dev.json`; the receipt
retains case names, manifest and console-log digests, tool versions, and the
zero-container cleanup result. The console log and per-case runtime artifacts
were not retained. The receipt labels this as a development-host run.

This matrix record alone is local process evidence. It does not establish a
clean macOS or Debian run, the reusable three-node/two-provider topology,
multi-provider Quote comparison, or chain-to-chain support.

### 2026-08-05 local multi-provider negotiation record

`scripts/test-lab-topology-quotes.sh` passed on macOS 26.4 arm64. It created
three distinct CLN roles with two normal channels per node, two relay
processes, and two independently keyed provider processes in `--no-spend`
mode. One requester discovered exactly one active provider and Offering on
each relay, reconstructed and verified both signed Quote deliveries through
the production requester engine, and selected one Quote using the
fixture-pinned total order. The mode-0600 retained record contains only public
node and event identifiers, normalized Quote terms, and the selection result;
the disposable containers and private root were absent after cleanup.

This negotiation record proves the reusable topology's multi-provider Quote
gate. By itself it does not prove funded two-provider execution, a clean-machine
run, or a public replacement claim.

### 2026-08-05 local funded multi-provider topology record

`scripts/test-lab-topology-funded.sh` passed on macOS 26.4 arm64. Its shared
regtest namespace contained two authenticated relays, two independently keyed
funded provider processes with separate Postgres databases and wallet seeds,
and provider-a/provider-b/wallet CLN nodes with two normal channels each. Each
provider mounted only its own read-only CLN RPC volume; the wallet driver
mounted only the wallet RPC volume and client seed.

One wallet verified two exact firm hard Quotes before creating either Order.
The fixture-pinned total order selected one provider. The other completed
request, accepted, and effective Cancel records followed by a cancelled Close,
zero external spend, and a terminal reservation release. The selected session
completed bilateral Contract verification, verify-before-fund authorization,
one Bitcoin funding broadcast, a three-confirmation provider claim, a paid
wallet Lightning invoice, and a completed Close. Independent queries against
both provider databases showed one released reservation each, no pending or
unresolved effects, and the expected completed/cancelled dispositions; both
provider metrics ended ready with no pending or unresolved watches.

The mode-0600 retained record contains normalized public identifiers, terms,
counts, confirmations, and durable-state summaries. Raw transactions, signed
records, gift wraps, credentials, and custody material stayed in the deleted
mode-0700 private root. This #32 process gate deliberately shares one bitcoind
namespace while isolating the two provider binaries, databases, wallet seeds,
and CLN sockets. It does not satisfy #18's separate-bitcoind independence gate.
This is local evidence; it does not establish clean macOS or Debian execution,
live deployment, or a public replacement claim.
