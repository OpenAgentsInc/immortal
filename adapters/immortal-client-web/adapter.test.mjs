import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"

import {
  ImmortalClient,
  ImmortalClientError,
  REQUESTER_API_SHA256,
} from "./adapter.mjs"

const wasmPath = new URL(
  "../../target/wasm32-unknown-unknown/release/immortal_client_web.wasm",
  import.meta.url,
)
const fixturePath = new URL(
  "../../tests/fixtures/nipmkt/swp-requester-api-v2.json",
  import.meta.url,
)
const sourceFixturePath = new URL(
  "../../tests/fixtures/nipmkt/swp-full-sessions-v1.json",
  import.meta.url,
)

async function client() {
  return ImmortalClient.instantiate(await readFile(wasmPath), {
    requesterApiSha256: REQUESTER_API_SHA256,
    sourceRevision: process.env.IMMORTAL_EXPECTED_SOURCE_REVISION,
  })
}

test("compiled WASM exposes the pinned executable requester API", async () => {
  const engine = await client()
  assert.equal(engine.metadata.abi_version, 1)
  assert.equal(engine.metadata.requester_api_sha256, REQUESTER_API_SHA256)
  assert.equal(engine.metadata.custody, "host_owned")
  assert.ok(engine.metadata.operations.includes("requester_order"))
  assert.ok(engine.metadata.operations.includes("prepare_funding_request"))
  assert.ok(engine.metadata.operations.includes("verify_before_fund"))
})

test("compiled WASM executes a signed requester order vector", async () => {
  const engine = await client()
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"))
  const source = JSON.parse(await readFile(sourceFixturePath, "utf8"))
  const input = resolve(fixture.vectors.requester_order_valid, fixture, source)
  const result = engine.invoke("requester_order", input)
  assert.equal(result.expected_event_id.length, 64)
  assert.equal(result.kind, 39606)
  assert.equal(result.pubkey, input.config.requester_pubkey)
  assert.equal(
    result.tags.find((tag) => tag[0] === "e")[1],
    input.quote.id,
  )
})

test("compiled WASM binds dynamic regtest input into requester RFQ identity", async () => {
  const engine = await client()
  const source = JSON.parse(await readFile(sourceFixturePath, "utf8"))
  const snapshot = source.flows.submarine.snapshot
  const original = snapshot.signed_records.find((record) => record.kind === 39604)
  const profile = JSON.parse(original.content).mkt_swp
  profile.constraints.input_amount = "150000"
  profile.constraints.maximum_total_fee = "5000"
  profile.constraints.destination_commitment_sha256 = "12".repeat(32)
  const input = {
    config: snapshot.config,
    created_at: original.created_at,
    distinct: original.tags.find((tag) => tag[0] === "d")[1],
    expiration: Number(
      original.tags.find((tag) => tag[0] === "expiration")[1],
    ),
    mkt_swp: profile,
  }
  const request = engine.invoke("requester_rfq", input)
  const bound = JSON.parse(request.content).mkt_swp.constraints
  assert.equal(bound.input_amount, "150000")
  assert.equal(bound.destination_commitment_sha256, "12".repeat(32))

  const mutated = structuredClone(input)
  mutated.mkt_swp.constraints.destination_commitment_sha256 =
    "13" + "12".repeat(31)
  const changed = engine.invoke("requester_rfq", mutated)
  assert.notEqual(changed.expected_event_id, request.expected_event_id)
})

test("compiled WASM preserves typed refusal and ABI mismatch", async () => {
  const engine = await client()
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"))
  const source = JSON.parse(await readFile(sourceFixturePath, "utf8"))
  const input = resolve(fixture.vectors.requester_order_expired, fixture, source)
  assert.throws(
    () => engine.invoke("requester_order", input),
    (error) =>
      error instanceof ImmortalClientError && error.code === "swp_quote_expired",
  )

  const bytes = await readFile(wasmPath)
  await assert.rejects(
    () =>
      ImmortalClient.instantiate(bytes, {
        requesterApiSha256: "00".repeat(32),
      }),
    (error) =>
      error instanceof ImmortalClientError &&
      error.code === "browser_requester_api_mismatch",
  )
})

function resolve(value, root, source) {
  if (Array.isArray(value)) {
    return value.map((item) => resolve(item, root, source))
  }
  if (!value || typeof value !== "object") {
    return value
  }
  if (Object.keys(value).length === 1 && "$artifact_ref" in value) {
    return resolve(pointer(root, value.$artifact_ref), root, source)
  }
  if (Object.keys(value).length === 1 && "$fixture_ref" in value) {
    return resolve(pointer(source, value.$fixture_ref), root, source)
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, resolve(item, root, source)]),
  )
}

function pointer(root, reference) {
  assert.ok(reference.startsWith("#/"))
  return reference
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((current, part) => current[part], root)
}
