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
