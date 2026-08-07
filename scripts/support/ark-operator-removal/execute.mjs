import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function argumentsByName(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument at ${name ?? "end of command"}`);
    }
    values.set(name.slice(2), value);
  }
  return values;
}

function required(values, name) {
  const value = values.get(name);
  if (!value) throw new Error(`missing --${name}`);
  return value;
}

function run(command, args) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function rejectCustodyFields(value) {
  const forbidden = new Set([
    "claim_key",
    "fee_key",
    "macaroon",
    "password",
    "preimage",
    "private_key",
    "private_nonce",
    "refund_key",
    "seed",
    "spend_key",
    "vtxo_key",
  ]);
  if (Array.isArray(value)) {
    for (const child of value) rejectCustodyFields(child);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key.toLowerCase().replaceAll("-", "_"))) {
        throw new Error(`exit package contains custody field ${key}`);
      }
      rejectCustodyFields(child);
    }
  }
}

async function endpointUnavailable(url) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
    return !response.ok;
  } catch {
    return true;
  }
}

async function waitFor(predicate, subject, timeoutMs = 60_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${subject}`);
}

const values = argumentsByName(process.argv.slice(2));
const sdkEntry = required(values, "sdk-entry");
const regtest = required(values, "regtest");
const packagePath = required(values, "package");
const receiptPath = required(values, "receipt");
const esploraUrl = required(values, "esplora-url");
const arkdUrl = required(values, "arkd-url");
const arkdAdminUrl = required(values, "arkd-admin-url");
const arkdWalletUrl = required(values, "arkd-wallet-url");

for (const endpoint of [arkdUrl, arkdAdminUrl, arkdWalletUrl]) {
  if (!(await endpointUnavailable(endpoint))) {
    throw new Error(`removed Ark operator endpoint is still reachable: ${endpoint}`);
  }
}

const sdk = await import(pathToFileURL(sdkEntry).href);
const packageBytes = readFileSync(packagePath);
const exitPackage = sdk.deserializeExitPackage(packageBytes.toString("utf8"));
if (
  exitPackage.mode !== "funded" ||
  exitPackage.steps.length === 0 ||
  exitPackage.steps.some((step) => step.kind === "bump")
) {
  throw new Error("loaded exit is not a fully pre-signed funded package");
}
rejectCustodyFields(exitPackage);
const provider = new sdk.EsploraProvider(esploraUrl, {
  forcePolling: true,
  pollingInterval: 250,
});
const events = [];
const executor = new sdk.UnilateralExit.Executor(exitPackage, provider, {
  pollIntervalMs: 250,
});
for await (const event of executor) {
  events.push({
    step_index: event.stepIndex,
    kind: event.kind,
    status: event.status,
    transaction_id: event.txid ?? null,
  });
  if (event.status === "failed") {
    throw new Error(`keyless exit step ${event.stepIndex} failed: ${event.reason}`);
  }
  if (event.status === "broadcast") {
    run(process.execPath, [regtest, "mine", "1"]);
  }
  if (event.status === "waiting_csv" && event.maturesAtHeight !== undefined) {
    const tip = await provider.getChainTip();
    run(process.execPath, [
      regtest,
      "mine",
      Math.max(1, event.maturesAtHeight - tip.height + 1).toString(),
    ]);
  }
}

await waitFor(
  async () => {
    const coins = await provider.getCoins(exitPackage.sweepAddress);
    return (
      coins
        .filter((coin) => coin.status.confirmed)
        .reduce((sum, coin) => sum + coin.value, 0) === exitPackage.totals.recoveredSats
    );
  },
  "the final participant Bitcoin output",
);
const confirmed = (await provider.getCoins(exitPackage.sweepAddress))
  .filter((coin) => coin.status.confirmed)
  .reduce((sum, coin) => sum + coin.value, 0);
const receipt = {
  schema: "openagents.immortal.ark-operator-removal-receipt.v1",
  package_sha256: createHash("sha256").update(packageBytes).digest("hex"),
  operator_endpoints_removed: true,
  execution_authority: "keyless_esplora",
  confirmed_recovered_sat: confirmed.toString(),
  expected_recovered_sat: exitPackage.totals.recoveredSats.toString(),
  completed_transaction_ids: events
    .filter((event) => event.status === "confirmed")
    .map((event) => event.transaction_id),
  events,
};
writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(receipt)}\n`);
