import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
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

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
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
const arkdUrl = required(values, "arkd-url");
const esploraUrl = required(values, "esplora-url");
const packagePath = required(values, "package");
const metadataPath = required(values, "metadata");
const arkdContainer = required(values, "arkd-container");

const requireFromSdk = createRequire(sdkEntry);
globalThis.EventSource = requireFromSdk("eventsource").EventSource;
const sdk = await import(pathToFileURL(sdkEntry).href);
const provider = new sdk.EsploraProvider(esploraUrl, {
  forcePolling: true,
  pollingInterval: 250,
});
const identity = sdk.SingleKey.fromRandomBytes();
const wallet = await sdk.Wallet.create({
  identity,
  arkServerUrl: arkdUrl,
  onchainProvider: provider,
  storage: {
    walletRepository: new sdk.InMemoryWalletRepository(),
    contractRepository: new sdk.InMemoryContractRepository(),
    virtualTxRepository: new sdk.InMemoryVirtualTxRepository(),
    exitDataCapture: { mode: "full" },
  },
  settlementConfig: false,
});
const receiveAddress = await wallet.getAddress();
if (!receiveAddress) throw new Error("Ark wallet did not produce a receive address");

run("docker", [
  "exec",
  arkdContainer,
  "ark",
  "send",
  "--to",
  receiveAddress,
  "--amount",
  "100000",
  "--password",
  "secret",
]);
await waitFor(
  async () => (await wallet.getVtxos()).reduce((sum, vtxo) => sum + vtxo.value, 0) >= 100_000,
  "the transferred participant VTXO",
);

const received = await wallet.getVtxos();
const receivedAmount = received.reduce((sum, vtxo) => sum + vtxo.value, 0);
await wallet.settle({
  inputs: received,
  outputs: [{ address: receiveAddress, amount: BigInt(receivedAmount) }],
});
await waitFor(async () => (await wallet.getVtxos()).length === 1, "the settled VTXO");

const settled = (await wallet.getVtxos())[0];
if (!settled) throw new Error("settlement produced no spendable VTXO");
const feeWallet = await sdk.OnchainWallet.create(identity, "regtest", provider);
const destinationIdentity = sdk.SingleKey.fromRandomBytes();
const destinationWallet = await sdk.OnchainWallet.create(
  destinationIdentity,
  "regtest",
  provider,
);
const options = {
  wallet,
  onchainWallet: feeWallet,
  sweepAddress: destinationWallet.address,
  feeRate: 2,
};
const quote = await sdk.UnilateralExit.estimate(options);
if (quote.vtxos.filter((vtxo) => !vtxo.skipped).length !== 1) {
  throw new Error("funded exit quote did not select exactly one VTXO");
}
const faucetAmount = quote.totals.fundingRequiredSats + 20_000;
run(process.execPath, [
  regtest,
  "faucet",
  feeWallet.address,
  (faucetAmount / 100_000_000).toFixed(8),
  "--confirm",
]);
await waitFor(
  async () => (await feeWallet.getCoins()).some((coin) => coin.status.confirmed),
  "the confirmed exit fee reserve",
);

const exitPackage = await sdk.UnilateralExit.prepare(options);
if (
  exitPackage.mode !== "funded" ||
  exitPackage.steps.length === 0 ||
  exitPackage.steps.some((step) => step.kind === "bump")
) {
  throw new Error("prepared exit is not a fully pre-signed funded package");
}
rejectCustodyFields(exitPackage);
run(process.execPath, [regtest, "mine", "1"]);
await waitFor(
  async () => {
    const first = exitPackage.steps[0];
    if (first.kind !== "broadcast") return false;
    try {
      return (await provider.getTxStatus(first.txid)).confirmed;
    } catch {
      return false;
    }
  },
  "the confirmed exit funding splitter",
);

const packageBytes = Buffer.from(sdk.serializeExitPackage(exitPackage));
writeFileSync(packagePath, packageBytes, { mode: 0o600 });
const operatorResponse = await fetch(`${arkdUrl}/v1/info`);
if (!operatorResponse.ok) throw new Error(`arkd info failed with ${operatorResponse.status}`);
const operator = await operatorResponse.json();
const metadata = {
  schema: "openagents.immortal.ark-operator-removal-preparation.v1",
  package_sha256: createHash("sha256").update(packageBytes).digest("hex"),
  operator_signer_pubkey: operator.signerPubkey,
  received_vtxo_id: `${settled.txid}:${settled.vout}`,
  received_amount_sat: settled.value.toString(),
  recovered_amount_sat: exitPackage.totals.recoveredSats.toString(),
  sweep_address: exitPackage.sweepAddress,
  step_count: exitPackage.steps.length,
  step_kinds: exitPackage.steps.map((step) => step.kind),
};
writeFileSync(metadataPath, `${JSON.stringify(metadata)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(metadata)}\n`);

// Ensure the package file remains a private artifact and metadata never grows
// a copy through a future refactor of this harness.
if (readFileSync(metadataPath, "utf8").includes(packageBytes.toString("hex"))) {
  throw new Error("metadata retained live exit-package bytes");
}
process.exit(0);
