#!/usr/bin/env node
/**
 * probe-input-names.mjs — recover circuit input SIGNAL NAMES from the
 * official .wasm artifacts (scratch tooling, not part of the server).
 *
 * Run:  node scripts/probe-input-names.mjs
 *
 * Background (verified in the installed circom_runtime source):
 * circom 2 wasm maps input signals by FNV-1a hash of the NAME
 * (_doCalculateWitness: fnvHash(key) -> getInputSignalSize/setInputSignal).
 * The wasm embeds NO name strings (FNV hashes only), so names can only be
 * learned by probing candidates. A name is FOUND when a witness attempt
 * with {[name]: ["1"]} fails with anything OTHER than a not-found error:
 *   - "Not all inputs have been set"  -> name exists (other inputs missing)
 *   - "Not enough values for input signal" -> name exists (array signal)
 * A name is ABSENT when the error is "Too many values for input signal"
 * (getInputSignalSize returns 0 for unknown names) or
 * "Signal <name> not found".
 *
 * Stops per circuit once found == getInputSize() (total scalar inputs).
 * Writes a JSON report to circuits/artifacts/PROBE.md (human-readable) and
 * prints the same to stdout. Exit code 0 even when names are NOT found —
 * a negative result is a result; it is recorded, not hidden.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const ART = path.join(REPO_ROOT, "circuits", "artifacts");

const CANDIDATES = {
  gatekeeper: [
    // SPEC.md envelope fields (snake + camel)
    "decision", "amount", "recipient", "condition_recipient", "conditionRecipient",
    "minimum", "public_balance", "publicBalance", "expiry_block", "expiryBlock",
    "current_block", "currentBlock", "max_transfer", "maxTransfer",
    "proof_tx", "proofTx", "registered_vk", "registeredVk", "proof_vk", "proofVk",
    "task_id", "taskId",
    // hash forms (circuit uses Poseidon internally — vks enter as hashes)
    "registeredVkHash", "proofVkHash", "taskHash", "vk", "proof", "publicSignals",
    // generic / structural
    "result", "valid", "isValid", "approved", "balance", "threshold", "expiry",
    "nonce", "salt", "commitment", "hash", "publicHash", "in", "input",
    "a", "b", "c", "out", "output",
    // extra variants tried in follow-up rounds
    "agentId", "taskIndex", "round", "mode", "version", "circuitVersion",
    "condition", "evaluation", "verdict", "outcome", "passed", "expired",
    "isExpired", "isReused", "proofValid", "validProof", "proofTxId", "txId",
    "txRef", "ref", "reference", "proofReference", "publicInputHash", "paramsHash",
    "conditionHash", "transferHash", "maxTransferHash", "expiryHash", "blockHash",
    "network", "publicSignals", "signals", "input", "inHash", "dataHash",
    "hashOfInputs", "evaluationHash", "checkHash", "decisionHash",
    "expectedDecisionHash", "approved", "isApproved", "allow", "allowed",
    "permitted", "gate", "gateId", "requestId", "request", "conditionId",
    "policyId", "ruleId", "proofId", "txHashHex", "proofTxHex", "sender",
    "receiver", "payee", "payer", "token", "tokenId", "chain", "block",
    "issuedAt", "deadlineAt", "expiryTime", "currentTime", "now", "reason",
    "reasonCode", "reason_code", "agent", "proofTxHashHex", "vkHashHex",
    "publicBalanceHex", "amountHex", "minimumHex", "recipientHex",
    "conditionRecipientHex", "maxTransferHex", "expiryBlockHex", "currentBlockHex",
    "taskIdHex", "decisionHex", "enabled", "active", "live", "open", "closed",
    "gatekeeper", "gatekeeperEvaluation", "main", "in0", "in1", "x", "y", "z",
    "input0", "publicInput", "proofTxHash", "txHash", "proofHash", "registeredHash",
    "vkHash", "registeredVkHex", "proofVkHex", "publicBalanceHash", "balanceHash",
    "inputHash", "poseidonHash", "expectedDecision", "actualDecision", "isValid",
    "approve", "result", "ok", "pass", "min", "max", "to", "from", "owner",
    "task", "chainId", "blockNumber", "timestamp", "deadline", "tx", "reused",
    "seen", "proofReused", "publicSignalsHash", "commitmentHash", "expected",
    "actual", "flag", "vkRegistered", "vkProof", "conditionVk", "publicVk",
    "registered", "recipientHash",
  ],
  vfyPolicy: [
    // SPEC.md Steal hash fields + envelope fields
    "strategyCommitment", "strategyCommitmentHash", "commitmentHash",
    "matchId", "match_id", "turn", "selfBalance", "opponentBalance",
    "circuitVersion", "publicInputsHash", "policy", "strategy", "fortified",
    "selfFortifiedUntilTurn", "opponentFortifiedUntilTurn", "balances",
    // variants found / tried in follow-up rounds
    "commitment", "turnNumber", "currentTurn", "round", "turnIndex",
    "strategyHash", "policyHash", "salt", "moves", "history", "previousAction",
    "nonce", "randomness", "seed", "secret", "selfFortified", "opponentFortified",
    "fortifiedUntilTurn", "extract", "hold", "extractAmount", "maxExtract",
    "balance", "self", "opponent", "version", "v1", "inputHash", "poseidonHash",
    "proof", "result", "decision", "isValid", "publicInputsHashHex", "hashHex",
    "commitmentHex", "actionType", "actionAmount", "amountToExtract",
    "turnsRemaining", "matchState", "stateHash", "policyProof", "verifier",
    "verify", "expected", "actual", "action", "amount", "hash", "in", "inputs", "data",
  ],
};

// De-duplicate while preserving order.
for (const k of Object.keys(CANDIDATES)) {
  CANDIDATES[k] = [...new Set(CANDIDATES[k])];
}

const ROOT_NODE_MODULES = path.join(REPO_ROOT, "node_modules");
const builder = (
  await import(
    pathToFileURL(path.join(ROOT_NODE_MODULES, "circom_runtime/js/witness_calculator.js")).href
  )
).default;

const report = { generated: new Date().toISOString(), circuits: {} };

for (const [circuit, wasmFile] of [
  ["gatekeeper", "gatekeeper.wasm"],
  ["vfyPolicy", "vfy-policy.wasm"],
]) {
  const buf = fs.readFileSync(path.join(ART, wasmFile));
  const wc = await builder(buf);
  const ex = wc.instance.exports;
  const totalInputs = ex.getInputSize();
  const witnessSize = ex.getWitnessSize();
  const found = [];

  for (const name of CANDIDATES[circuit]) {
    if (found.length >= totalInputs) break;
    try {
      await wc.calculateWitness({ [name]: ["1"] }, true);
      // No error at all would mean a 1-input circuit — impossible here
      // (totalInputs > 1), so treat as found too.
      found.push(name);
    } catch (e) {
      const msg = String(e && e.message ? e.message : e);
      if (/Not all inputs have been set/.test(msg) || /Not enough values for input signal/.test(msg)) {
        found.push(name);
      } else if (/Too many values for input signal/.test(msg) || /Signal .* not found/.test(msg)) {
        // absent — ignore
      } else {
        // Any other error after the name passed the per-signal check also
        // means the name exists (e.g. an in-circuit assert on a dummy value).
        found.push(`${name} (note: ${msg.split("\n")[0].slice(0, 120)})`);
      }
    }
  }

  report.circuits[circuit] = {
    wasm: wasmFile,
    totalInputs,
    witnessSize,
    found,
    foundCount: found.length,
    complete: found.length >= totalInputs,
  };

  console.log(`=== ${circuit} (${wasmFile}) — getInputSize=${totalInputs}, witness=${witnessSize} ===`);
  console.log(`  FOUND ${found.length}/${totalInputs}: ${found.join(", ") || "(none)"}`);
  console.log(`  COMPLETE: ${found.length >= totalInputs ? "yes — all input names recovered" : "NO — input set incomplete"}`);
}

const mdLines = [
  "# Input-name probe report (generated by scripts/probe-input-names.mjs)",
  "",
  `Generated: ${report.generated}`,
  "",
  "Method: FNV-1a oracle via circom_runtime witness calculation — see the",
  "script header. A name counts as FOUND only when a witness attempt with",
  "`{[name]: [\"1\"]}` gets past the per-signal check (error \"Not all inputs",
  "have been set\" / \"Not enough values\" / an in-circuit assert).",
  "",
];
for (const [circuit, r] of Object.entries(report.circuits)) {
  mdLines.push(
    `## ${circuit}`,
    "",
    `- wasm: \`${r.wasm}\`, total scalar inputs (getInputSize): ${r.totalInputs}, witness size: ${r.witnessSize}`,
    `- found ${r.foundCount}/${r.totalInputs} — ${r.complete ? "COMPLETE" : "INCOMPLETE"}`,
    "",
    ...r.found.map((f) => `- \`${f}\``),
    "",
  );
}
fs.writeFileSync(path.join(ART, "PROBE.md"), mdLines.join("\n") + "\n");
console.log(`\nWrote ${path.join(ART, "PROBE.md")}`);
