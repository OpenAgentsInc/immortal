> Status: draft. Written for the Coder Cloud service and verified by its
> `coder-auth` crate. Kinds `27240` and `27241` are reserved by this draft.

NIP-CA
======

Coder authentication
--------------------

`draft` `optional`

This NIP defines how a client authenticates to the Coder Cloud service and
how the service accepts spending authority, using signed Nostr events in
place of bearer tokens. It profiles two official NIPs and adds two
ephemeral kinds:

| Kind    | Name                  | Signed by          | Defined in |
| ------- | --------------------- | ------------------ | ---------- |
| `27235` | HTTP request auth     | The caller's key   | NIP-98     |
| `22242` | Session challenge     | The caller's key   | NIP-42     |
| `27240` | Coder spending grant  | A trusted issuer   | This NIP   |
| `27241` | Coder identity token  | A trusted issuer   | This NIP   |

All four kinds are ephemeral (`20000` to `29999`). A relay never stores
them, and a client never publishes them. They travel in HTTP headers and
socket messages between a client and the service.

## Terms

- **Service**: the Coder Cloud HTTP and MCP surface, identified by its
  absolute URL, for example `https://coder.openagents.com/mcp`.
- **Caller key**: the secp256k1 keypair a client holds. Its x-only public
  key is the caller's identity on the wire.
- **Trusted issuer**: a key the service operator lists in its
  configuration. The account service (`openagents.com`) holds one; an
  operator running the service locally lists their own key so they can
  mint for themselves.
- **Account**: the account identifier the account service assigns. It is
  an opaque string.

## Tags this NIP defines

| Tag          | Value                                              | Used by         |
| ------------ | -------------------------------------------------- | --------------- |
| `aud`        | `coder` on an identity token, `coder-grant` on a grant | `27240`, `27241` |
| `account`    | The account identifier                             | `27240`, `27241`, `27235` |
| `login`      | The GitHub login the account maps to               | `27241`, `27235` |
| `github`     | The GitHub account id, as a decimal string         | `27241`, `27235` |
| `allowance`  | The spending bound, in cents, as a decimal string  | `27240`         |
| `grant`      | The unique grant identifier                        | `27240`         |
| `expiration` | Unix seconds after which the event is void (NIP-40) | `27240`, `27241` |
| `p`          | The x-only public key the event is bound to        | `27240`, `27241` |
| `token`      | A base64 kind-`27241` event carried inside a request auth | `27235` |

The `expiration` tag is the NIP-40 tag, so a general-purpose validator
already refuses an expired event. `p` is the NIP-01 pubkey tag, so a
bound event names the key it is bound to in the field every relay indexes.

## Kind 27241: Coder identity token

A trusted issuer signs an identity token to assert that an account maps to
a GitHub identity. It replaces the Ed25519 JWT the account service mints
today, claim for claim.

```jsonc
{
  "kind": 27241,
  "pubkey": "<trusted issuer>",
  "created_at": 1756700000,
  "tags": [
    ["aud", "coder"],
    ["account", "account-1"],
    ["login", "octavia"],
    ["github", "42424242"],
    ["expiration", "1756700600"],
    ["p", "<caller key, optional>"]
  ],
  "content": "",
  "sig": "<schnorr>"
}
```

Rules:

- `aud` MUST be `coder`. `account`, `login`, `github`, and `expiration`
  MUST each appear exactly once. `github` MUST be a positive integer.
  `login` MUST be 1 to 39 characters.
- Without a `p` tag, the token is a bearer credential: whoever presents it
  is the identity it names, for as long as it lives. This is the shape the
  JWT has today, and a client that holds no key presents it as
  `Authorization: Nostr <base64 event>`.
- With a `p` tag, the token is bound to a caller key. The service accepts
  it only inside a kind-`27235` request auth signed by that key (see the
  `token` tag below). A bound token presented on its own is refused.

## Kind 27240: Coder spending grant

A trusted issuer signs a grant to let the service spend against an account
up to a bound. The service verifies it locally and records it once by grant
id; a repeat presentation returns the recorded grant.

```jsonc
{
  "kind": 27240,
  "pubkey": "<trusted issuer>",
  "created_at": 1756700000,
  "tags": [
    ["aud", "coder-grant"],
    ["account", "account-1"],
    ["allowance", "500"],
    ["grant", "5f1c3a0e-9b0c-4c8d-8f3a-2e1d6c7b8a90"],
    ["expiration", "1756786400"],
    ["p", "<delegatee key, optional>"]
  ],
  "content": "",
  "sig": "<schnorr>"
}
```

Rules:

- `aud` MUST be `coder-grant`. `account`, `allowance`, `grant`, and
  `expiration` MUST each appear exactly once.
- `allowance` MUST be a positive integer in cents. The service enforces
  its own ceiling and refuses a grant above it even when the signature
  verifies.
- `grant` MUST be unique per issuer. It keys acceptance and later
  settlement.
- The `p` tag names the delegatee, in the sense of NIP-26: the key that
  may spend the grant. A grant without `p` is a bearer grant.

## Kind 27235: request auth, Coder profile

The service accepts `Authorization: Nostr <base64 event>` on every HTTP
route, as NIP-98 defines it: a kind-`27235` event whose `u` tag is the
absolute request URL, whose `method` tag is the HTTP method, and whose
`payload` tag is the lowercase hex SHA-256 of the request body when the
request has one.

The service adds these rules:

- `created_at` MUST be within the service's clock-skew bound of its own
  clock. The default bound is 60 seconds.
- The event id is single-use. The service remembers each accepted id
  until the skew bound passes and refuses a repeat.
- The service resolves the caller's identity in this order:
  1. A `token` tag carrying a base64 kind-`27241` event whose `p` tag is
     the request auth's `pubkey`. The token's issuer MUST be trusted and
     the token MUST be unexpired. The identity comes from the token.
  2. If the request auth's own `pubkey` is a trusted issuer, the identity
     comes from `account`, `login`, and `github` tags on the request auth
     itself. This is how an operator uses their own key against their own
     service.
  3. Otherwise the request is refused: the key is valid, but the service
     knows nobody by it.

## Kind 22242: session challenge, Coder profile

A socket or an MCP session that outlives one request authenticates with
NIP-42. The service sends a challenge, and the client answers with a
kind-`22242` event whose `relay` tag is the service URL and whose
`challenge` tag is the challenge string. The service adds these rules:

- A challenge is single-use and expires after a bounded time. The default
  is 10 minutes.
- `created_at` MUST be within the same clock-skew bound as request auth.
- The authenticated key is resolved to an identity by the same rules as
  request auth, with the `token` tag on the kind-`22242` event.

## Verification

Every event is verified by the NIP-01 rules first: the `id` is the SHA-256
of the canonical serialization, and `sig` is a BIP-340 Schnorr signature of
`id` by `pubkey`. Then the kind's rules apply. A trusted issuer is matched
by exact x-only public key; the operator configures issuers as a list of
`npub` strings (NIP-19).

## Security notes

- A bearer token or bearer grant carries the same risk as a JWT: anyone who
  holds it can use it until it expires. Issuers SHOULD mint short lifetimes
  for bearer shapes and SHOULD prefer bound shapes once clients hold keys.
- The clock-skew bound and the single-use id together bound replay of a
  request auth to one delivery inside the window.
- The service never learns a secret key. An issuer's `nsec` stays with the
  issuer; a caller's `nsec` stays with the caller.
