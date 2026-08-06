# Local NIP-MKT development

This runbook starts a loopback Immortal relay with disposable Postgres state,
then drives a complete two-actor NIP-MKT session through it. It supports macOS
Homebrew Postgres, Postgres already on `PATH`, and Docker or Podman as a
fallback.

## Prerequisites

Install Rust and either Postgres or a container runtime. On macOS, the native
path is:

```sh
brew install rust postgresql@17 curl
```

On Debian:

```sh
sudo apt-get update
sudo apt-get install -y cargo postgresql curl build-essential
```

Docker or Podman can replace the local Postgres package on either platform.

## Start the relay

From the repository root:

```sh
./scripts/dev-relay.sh
```

The script builds Immortal and listens at `ws://127.0.0.1:18080`. It creates a
temporary Postgres cluster when native tools are available; otherwise it uses
a temporary `postgres:17-alpine` container. Ctrl-C stops the relay and removes
only the cluster or container created by that invocation.

To use an existing development database, set
`IMMORTAL_DEV_DATABASE_URL`. The script never removes an externally supplied
database. Set `IMMORTAL_DEV_RELAY_PORT` to change the loopback port.

Inspect the running process from another terminal:

```sh
curl -fsS http://127.0.0.1:18080/health
curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:18080/
```

The launcher sets `IMMORTAL_RELAY_URL` to the printed loopback URL because
the market smoke needs NIP-42 recipient authentication. Authentication is not
required for public discovery or publication.

## Seed a market session

In another terminal:

```sh
./scripts/dev-market-seed.sh
```

The command generates two throwaway actors, publishes a provider profile and
offering, authenticates a recipient-gated subscription for each actor, and
drives this wrapped path:

```text
RFQ -> Quote -> Order -> Status(completed) -> Close(completed)
```

Every private record is signed before encryption and sent twice using
independent NIP-59 material: one gift wrap for the counterparty and one for
the author's recovery history. Each recipient decrypts and validates the
exact inner bytes. The JSON output contains actor public keys, public head
IDs, all inner IDs, both outer wrap IDs for every step, and the final state.
Private keys are never printed or stored.

Relay acceptance proves storage and recipient-gated transport. The smoke's
`completed` value is a coordination claim; it does not prove execution,
payment, or settlement.

To target another port on loopback:

```sh
IMMORTAL_DEV_RELAY_URL=ws://127.0.0.1:19090 ./scripts/dev-market-seed.sh
```

The seed command refuses non-loopback and `wss://` targets so throwaway local
traffic cannot be sent to a production relay by mistake.

## Run the no-spend provider

With `scripts/dev-relay.sh` running, start the separate provider process with
a development-only Nostr identity key:

```sh
IMMORTAL_PROVIDER_IDENTITY_SECRET='<64-lower-hex-development-secret>' \
IMMORTAL_PROVIDER_RELAY_URL='ws://127.0.0.1:18080' \
  ./scripts/dev-market-provider.sh
```

The URL must resolve to loopback. The identity signs provider records but is
not a wallet or custody key. The process publishes its Provider Profile and
Offering, answers complete RFQs, stores its own NIP-59 recovery wraps in the
relay, and resumes those sessions after restart. Ctrl-C stops only the
provider process.

Run the reproducible separate-process proof with:

```sh
./scripts/test-dev-market-provider.sh
```

The script creates and removes a disposable relay/Postgres instance, builds
and launches `immortal-provider --no-spend`, restarts that process, and drives
submarine, reverse, and chain sessions through bilateral contracts, mutual
cancellation, and provider-authored zero-loss Close records. It performs no
funding, payment, wallet, node, or broadcast action.

## Run the disposable Liquid rail

The Liquid conformance gate owns a temporary elementsd regtest node, wallet,
dynamic loopback ports, image, container, and state directory. It verifies
exact funding and unilateral-exit bytes, own-output unblinding, already-known
replay, and ownership-checked teardown:

```sh
./scripts/test-provider-liquid.sh
```

The expanded adversarial gate adds Liquid submarine, Liquid reverse,
BTC→L-BTC, and L-BTC→BTC sessions against both funded provider identities.
It also executes a provider-absent presigned Liquid refund and a
coordinator-absent direct Liquid claim with Lightning settlement:

```sh
./scripts/test-lab-adversarial.sh --all
```

These commands use throwaway regtest custody only. They do not configure a
production elementsd wallet or establish a live deployment claim.

## Point clients at the relay

Set the client relay URL to `ws://127.0.0.1:18080`. NIP-42 authentication is
required for every gift-wrap read surface; discovery kinds 39600-39603 remain
public. Stopping `dev-relay.sh` discards the default database, so run the smoke
again after each restart.
