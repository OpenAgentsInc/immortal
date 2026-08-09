# Provider price-feed packet

This document specifies the provider-local price-feed packet used by
`immortal-provider`. It does not change MKT-SWP event kinds or the signed
Quote `price_feed` member. That member remains `null` until the requester can
reproduce the feed calculation defined by MKT-SWP section 3.4.

## Packet

The sidecar writes one strict JSON object:

```json
{
  "schema": "openagents.immortal.provider-price-feed.v1",
  "source": {
    "venue": "lnmarkets",
    "environment": "signet",
    "instrument": "btc_usd"
  },
  "index_price_usd_cents": "6471550",
  "realized_volatility_bps": "10000",
  "realized_volatility_window_seconds": 86400,
  "observed_at": 1785859200,
  "max_age_seconds": 30
}
```

The schema has no optional or unknown members. Source identity members are
lowercase machine identifiers of 1 through 64 bytes. The index is a positive
canonical decimal string in USD cents per bitcoin, at most 10,000,000,000.
Realized volatility is the root-sum-square of log returns over the named
window, expressed as a canonical non-negative basis-point string and bounded
at 100,000. The window is 1 through 604,800 seconds. `observed_at` is a Unix
timestamp in seconds. `max_age_seconds` is 1 through 3,600 seconds.

## Validation and fallback

The provider receives the quote creation timestamp as an input. It performs
no clock read in the pricing module. An observation from the future, an
observation older than `observed_at + max_age_seconds`, an invalid member, an
invalid source identity, or an invalid file produces the static pricing path.
Network access is never required to quote. The packet carries public market
data only. It must contain no venue credential or user data.

The funded provider can read the packet from the absolute path in
`IMMORTAL_PROVIDER_PRICE_FEED_FILE`. The file must be a bounded regular file,
not a symbolic link. The producer should replace it atomically. The provider
does not fetch the venue and has no HTTP dependency.

## Pricing

The operator's static spread is the spread at a reference realized volatility
of 5,000 basis points. For a fresh packet:

```text
effective_spread_bps = min(1000,
  floor(static_spread_bps * realized_volatility_bps / 5000))
```

This formula widens or narrows the provider fee while keeping it within the
existing 0 through 1,000 basis-point bound. A static spread of zero stays
zero. Missing, invalid, and stale packets use the configured static spread.

The provider values native satoshi amounts in USD cents with integer floor
rounding:

```text
usd_cents = floor(satoshis * index_price_usd_cents / 100000000)
```

The USD values are provider-local audit metadata. They do not change the
signed asset amounts. The provider fee uses the effective spread. The exact
miner-fee budget, routing budget, amount equation, dust floor, reservation,
and capacity checks are unchanged.

## Fixture

`tests/fixtures/provider/price-feed-v1.json` pins one fresh application and
one stale fallback. The provider machine contract binds its exact digest.
