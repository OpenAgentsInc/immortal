# Immortal invariants

## Provider price feed

- The price-feed packet is public market data. It contains no exchange
  credential, user data, wallet material, or node credential.
- Immortal does not fetch venue data. The funded provider can read one bounded
  local regular nonsymlink file. The relay never reads the file.
- A missing, malformed, future-dated, or stale packet uses the configured
  static spread. Feed availability does not block a native-asset Quote.
- A fresh packet may change only the provider spread, the resulting provider
  fee and output amount, and provider-local USD valuation metadata. It does
  not change the amount equation, miner-fee arithmetic, routing fees,
  capacity, reservation, asset units, finality, or settlement authority.
- The MKT-SWP Quote `price_feed` member remains `null`. Provider-local data is
  not presented as a requester-verifiable feed pin.

## Network intents

- Revision-2 effectful intents are typed signed events with a client-supplied
  idempotency key, bounded nonce window, and a provider-signed acknowledgment
  distinct from every outcome.
- One accepted intent permits one external-effect attempt. Exact replay,
  restart, relay duplication, timeout, and typed re-drive return durable signed
  records and never create another attempt.
- A response-encryption key is transport authority only. Authorization remains
  with the signed identity event.
- Re-drive is read-only. Missing history stays explicitly missing; no relay or
  provider synthesizes event history from current mutable state.
- A revision-2 terminal Order has one canonical provider-signed Settlement
  Receipt. Its exact Order, acknowledgment, Quote, Close, amounts, rails, fees,
  times, outcome, and optional requester confirmation are event-verifiable;
  external settlement remains bounded by native rail evidence.
