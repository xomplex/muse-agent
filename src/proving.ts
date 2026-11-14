/**
 * proving.ts — Groth16 proof generation for zkVerify Agent Games.
 *
 * Uses the PLATFORM's official published circuits (see SPEC.md and
 * circuits/README.md). No local Circom build, no trusted setup — the
 * platform publishes the .wasm/.zkey artifacts and we prove with snarkjs.
 *
 * Expected duration: fullProve on these small circuits takes seconds
 * (single-digit, dominated by witness generation + proving). No artificial
 * timeout is applied; callers enforce the platform's 60s response budget.
 *
 * INPUT SIGNAL NAMES (recovered — see circuits/artifacts/PROBE.md):
 * The platform does NOT publish the circuits' input names. They were
 * recovered by probing the official .wasm artifacts with the FNV-1a oracle
 * in circom_runtime (scripts/probe-input-names.mjs). The wasm stores only
 * FNV hashes of names, so names were found by testing candidates from
 * SPEC.md — and verified by a real fullProve + local-verify round-trip.
 *
 * gatekeeper (13/13 recovered, 12 public + 1 private):
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt
 *   - registeredVkHash / proofVkHash are Poseidon hashes of the vks (the
 *     circuit compares them; equal values pass the VK check). They are
 *     supplied as field elements (decimal strings) — hex envelope values
 *     are converted with BigInt, see buildGatekeeperCircuitInputs().
 *   - decision: 1 = APPROVE, 0 = REJECT. VERIFIED by live round-trips:
 *     all-conditions-true + decision=1 verifies; amount>maxTransfer +
 *     decision=0 verifies; the same violation + decision=1 FAILS at
 *     witness time ("Assert Failed. Error in template
 *     GatekeeperEvaluation_79 line: 102") — the circuit asserts
 *     decision == the evaluated condition, so a wrong decision cannot
 *     even produce a witness, let alone a proof.
 *   - Public-signal order (from the live witness, 13 signals):
 *     [Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
 *     publicBalance, expiryBlock, currentBlock, recipient,
 *     conditionRecipient, amount, maxTransfer, decision, taskId].
 *     Poseidon([salt, taskId]) was confirmed EXACTLY with circomlibjs
 *     (changing salt or taskId changes signal 0; changing vks/minimum
 *     does not). salt is the only private input (blinding for the task
 *     commitment); the other 12 inputs are public.
 *   - recipient / conditionRecipient are addresses as decimal integers.
 *   - taskId encoding (ASSUMPTION, documented in PROVING.md): an
 *     alphanumeric task id such as "gk_24_9d1" is encoded as the
 *     big-endian integer of its UTF-8 bytes. The platform's exact
 *     encoding is unpublished; the proof verifies cryptographically for
 *     any field element, but the platform's reading of public signal 12
 *     depends on this encoding matching theirs.
 *   - salt: if the caller does not supply one, generateProof draws a
 *     fresh random 31-byte field element per proof (private blinding).
 *   - The server passes envelope-style inputs (registered_vk, proof_vk,
 *     public_balance, task_id, proof_tx, ...); generateProof translates
 *     them to the circuit names and DROPS proof_tx (not a circuit input).
 *     If the caller does not pass a decision, it is DERIVED from the
 *     same rule as SPEC.md (all five conditions hold -> 1, else 0).
 *     Prefer passing the server's decision explicitly — derivation cannot
 *     see off-circuit reject reasons (e.g. PROOF_REUSED).
 *
 * vfyPolicy (9/17 recovered — INCOMPLETE, do NOT use for live proofs):
 *   commitment, matchId, turnNumber, selfBalance, opponentBalance,
 *   action, amount, circuitVersion, salt
 *   The remaining 8 inputs are private policy inputs whose names are not
 *   recoverable from the published material. generateProof("steal") will
 *   therefore throw ("Not all inputs have been set") — an honest error,
 *   never a fake proof. See PROVING.md.
 *
 * A proof is never fabricated: if fullProve throws, the error propagates
 * unchanged (the server maps it to proof:null).
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as snarkjs from "snarkjs";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";

export interface ProofRequest {
  track: "gatekeeper" | "steal";
  circuitInputs: Record<string, unknown>;
  publicInputs: string[];
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
  circuit: string;
  circuitVersion: string;
  placeholder: boolean;
}

/** Published platform vkHashes (public constants from circuit-info.json). */
export const PUBLISHED_VK_HASH: Record<string, string> = {
  gatekeeper:
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  vfyPolicy:
    "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
};

/** Recovered gatekeeper input names (13/13 — see PROBE.md). */
export const GATEKEEPER_INPUT_NAMES = [
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
  "salt",
] as const;

/** Recovered vfyPolicy input names (9/17 — INCOMPLETE, see module docs). */
export const VFYPOLICY_INPUT_NAMES_KNOWN = [
  "commitment",
  "matchId",
  "turnNumber",
  "selfBalance",
  "opponentBalance",
  "action",
  "amount",
  "circuitVersion",
  "salt",
] as const;

const TRACK_FILES: Record<
  ProofRequest["track"],
  { wasm: string; zkey: string; vkey: string; circuit: string }
> = {
  gatekeeper: {
    wasm: "gatekeeper.wasm",
    zkey: "gatekeeper_final.zkey",
    vkey: "gatekeeper.vkey.json",
    circuit: "gatekeeper",
  },
  steal: {
    wasm: "vfy-policy.wasm",
    zkey: "vfy-policy_final.zkey",
    vkey: "vfy-policy.vkey.json",
    circuit: "vfyPolicy",
  },
};

/**
 * Resolve the artifacts directory. Order:
 *  1. $CIRCUIT_DIR (resolved against process.cwd() if relative)
 *  2. <repo-root>/circuits/artifacts (works from dist/ and from src/)
 */
export function resolveArtifactDir(): string {
  const candidates: string[] = [];
  if (process.env.CIRCUIT_DIR) {
    candidates.push(path.resolve(process.env.CIRCUIT_DIR));
  }
  candidates.push(
    path.resolve(__dirname, "..", "..", "circuits", "artifacts"), // dist/*.js -> repo root
    path.resolve(__dirname, "..", "circuits", "artifacts"), // src/*.ts (ts-node/dev)
  );
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "gatekeeper.wasm"))) return dir;
  }
  // Nothing found yet — return the first candidate so error messages point
  // at the configured location.
  return candidates[0];
}

/** Read the published vkHash for a circuit from circuit-info.json, falling
 * back to the hardcoded published constant (same value) if the file is
 * unreadable. Never throws for a missing info file. */
export function publishedVkHash(circuit: "gatekeeper" | "vfyPolicy"): string {
  const dir = resolveArtifactDir();
  try {
    const info = JSON.parse(
      fs.readFileSync(path.join(dir, "circuit-info.json"), "utf8"),
    ) as { circuits?: Record<string, { vkHash?: string }> };
    const h = info.circuits?.[circuit]?.vkHash;
    if (typeof h === "string" && h.startsWith("0x")) return h;
  } catch {
    // fall through to the published constant below
  }
  return PUBLISHED_VK_HASH[circuit];
}

/**
 * Translate caller-supplied gatekeeper inputs into the circuit's 13 named
 * signals (see module docs for the recovered names).
 *
 * Accepts BOTH spellings:
 *  - envelope-style (what src/server.ts passes): registered_vk, proof_vk,
 *    minimum, public_balance, expiry_block, current_block, recipient,
 *    condition_recipient, amount, max_transfer, task_id, decision
 *    ("APPROVE"/"REJECT"), plus proof_tx (DROPPED — not a circuit input).
 *  - circuit-style (already the 13 names): registeredVkHash, proofVkHash,
 *    publicBalance, expiryBlock, currentBlock, conditionRecipient,
 *    maxTransfer, taskId, decision ("1"/"0"), salt.
 *
 * Conversions:
 *  - 0x-hex values (vk hashes, addresses) -> decimal field-element strings
 *    via BigInt. Decimal strings/numbers pass through unchanged.
 *  - taskId: a numeric string stays numeric; an alphanumeric id such as
 *    "gk_24_9d1" is encoded as the big-endian integer of its UTF-8 bytes
 *    (ASSUMPTION — see module docs; the platform's encoding is unpublished).
 *  - decision: explicit "APPROVE"/"REJECT"/1/0/"1"/"0" wins; when absent it
 *    is DERIVED from the SPEC.md rule (vk equal AND balance>=minimum AND
 *    current<=expiry AND recipient==condition AND amount<=max -> 1 else 0).
 *  - salt: supplied value wins, otherwise a fresh random 31-byte field
 *    element is drawn per call (private blinding for Poseidon(salt,taskId)).
 *
 * Throws a clear Error listing any missing required input. Unknown keys
 * (proof_tx, ...) are ignored, so extra envelope fields never break proving.
 */
export function buildGatekeeperCircuitInputs(
  input: Record<string, unknown>,
): Record<string, string> {
  const pick = (...keys: string[]): unknown => {
    for (const k of keys) if (input[k] !== undefined) return input[k];
    return undefined;
  };

  const toField = (value: unknown, field: string): string => {
    if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 0) {
        throw new Error(`gatekeeper input ${field}: must be a non-negative integer, got ${value}`);
      }
      return BigInt(value).toString();
    }
    if (typeof value === "string") {
      const s = value.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
      if (/^[0-9]+$/.test(s)) return s.replace(/^0+(?=\d)/, "") || "0";
      throw new Error(
        `gatekeeper input ${field}: expected a decimal or 0x-hex integer, got ${JSON.stringify(value)}`,
      );
    }
    throw new Error(`gatekeeper input ${field}: expected a number or numeric string, got ${typeof value}`);
  };

  const toTaskIdField = (value: unknown, _field?: string): string => {
    if (typeof value === "number") return BigInt(value).toString();
    if (typeof value === "string") {
      const s = value.trim();
      if (/^[0-9]+$/.test(s)) return s.replace(/^0+(?=\d)/, "") || "0";
      if (s.length === 0) throw new Error("gatekeeper input taskId: empty string");
      // ASSUMPTION: alphanumeric id -> big-endian integer of UTF-8 bytes.
      return BigInt("0x" + Buffer.from(s, "utf8").toString("hex")).toString();
    }
    throw new Error(`gatekeeper input taskId: expected a string or number, got ${typeof value}`);
  };

  const required: [string, string[], ((v: unknown, field: string) => string)?][] = [
    ["registeredVkHash", ["registeredVkHash", "registeredVk", "registered_vk"], toField],
    ["proofVkHash", ["proofVkHash", "proofVk", "proof_vk"], toField],
    ["minimum", ["minimum"], toField],
    ["publicBalance", ["publicBalance", "public_balance"], toField],
    ["expiryBlock", ["expiryBlock", "expiry_block"], toField],
    ["currentBlock", ["currentBlock", "current_block"], toField],
    ["recipient", ["recipient"], toField],
    ["conditionRecipient", ["conditionRecipient", "condition_recipient"], toField],
    ["amount", ["amount"], toField],
    ["maxTransfer", ["maxTransfer", "max_transfer"], toField],
    ["taskId", ["taskId", "task_id"], toTaskIdField],
  ];

  const out: Record<string, string> = {};
  const missing: string[] = [];
  for (const [circuitName, aliases, convert] of required) {
    const raw = pick(...aliases);
    if (raw === undefined) {
      missing.push(circuitName);
      continue;
    }
    out[circuitName] = (convert ?? toField)(raw, circuitName);
  }
  if (missing.length > 0) {
    throw new Error(
      `gatekeeper inputs missing required field(s): ${missing.join(", ")}. ` +
        `Provide the envelope fields (registered_vk, proof_vk, minimum, ` +
        `public_balance, expiry_block, current_block, recipient, ` +
        `condition_recipient, amount, max_transfer, task_id) or the circuit ` +
        `names directly — see PROVING.md.`,
    );
  }

  // decision: explicit wins; otherwise derive from the SPEC.md rule.
  const rawDecision = pick("decision");
  if (rawDecision === undefined) {
    const vkEqual = out.registeredVkHash === out.proofVkHash;
    const balanceOk = BigInt(out.publicBalance) >= BigInt(out.minimum);
    const expiryOk = BigInt(out.currentBlock) <= BigInt(out.expiryBlock);
    const recipientOk = out.recipient === out.conditionRecipient;
    const amountOk = BigInt(out.amount) <= BigInt(out.maxTransfer);
    out.decision = vkEqual && balanceOk && expiryOk && recipientOk && amountOk ? "1" : "0";
  } else if (rawDecision === "APPROVE" || rawDecision === 1 || rawDecision === "1") {
    out.decision = "1";
  } else if (rawDecision === "REJECT" || rawDecision === 0 || rawDecision === "0") {
    out.decision = "0";
  } else {
    throw new Error(
      `gatekeeper input decision: expected "APPROVE"/"REJECT"/1/0, got ${JSON.stringify(rawDecision)}`,
    );
  }

  // salt: supplied wins, otherwise fresh random blinding per proof.
  const rawSalt = pick("salt");
  out.salt =
    rawSalt === undefined
      ? BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString()
      : toField(rawSalt, "salt");

  return out;
}

export async function generateProof(req: ProofRequest): Promise<ProofResult> {
  const files = TRACK_FILES[req.track];
  const dir = resolveArtifactDir();
  const wasmPath = path.join(dir, files.wasm);
  const zkeyPath = path.join(dir, files.zkey);

  for (const [label, p] of [
    ["wasm", wasmPath],
    ["zkey", zkeyPath],
  ] as const) {
    if (!fs.existsSync(p)) {
      throw new Error(
        `Missing ${req.track} circuit artifact (${label}): ${p}. ` +
          `Run: bash scripts/download-artifacts.sh`,
      );
    }
  }

  if (req.track === "steal") {
    // vfyPolicy input names are only 9/17 recovered (see module docs).
    // Without the full input set fullProve cannot run; fail loudly with
    // instructions instead of guessing names or faking a proof.
    throw new Error(
      "Steal (vfyPolicy) circuit input signal names are not fully published: " +
        "only 9 of 17 inputs recovered (see circuits/artifacts/PROBE.md). " +
        "generateProof cannot build a valid witness until the platform " +
        "publishes the remaining private input names — see SPEC.md.",
    );
  }

  // Throws unchanged on bad inputs (e.g. wrong input arity / unknown
  // signal name — snarkjs reports "Signal <name> not found" or
  // "Not all inputs have been set"). The server maps this to proof:null;
  // a proof is never fabricated.
  // Gatekeeper: translate envelope-style inputs to the 13 circuit signals
  // (buildGatekeeperCircuitInputs drops proof_tx, converts hex, derives
  // decision when absent, draws a random salt when absent).
  const circuitInputs =
    req.track === "gatekeeper"
      ? buildGatekeeperCircuitInputs(req.circuitInputs)
      : req.circuitInputs;
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    wasmPath,
    zkeyPath,
  );

  return {
    proof,
    publicSignals: (publicSignals as string[]).map(String),
    circuit: files.circuit,
    circuitVersion: publishedVkHash(files.circuit as "gatekeeper" | "vfyPolicy"),
    placeholder: false,
  };
}

/**
 * Verify a Groth16 proof locally against the exported platform VK
 * (circuits/artifacts/<circuit>.vkey.json). Used by tests and by the server
 * as a pre-flight check. Returns true only if snarkjs verification passes.
 */
export async function verifyProofLocally(
  proof: unknown,
  publicSignals: string[],
  circuit: "gatekeeper" | "vfyPolicy",
): Promise<boolean> {
  const files =
    circuit === "gatekeeper" ? TRACK_FILES.gatekeeper : TRACK_FILES.steal;
  const dir = resolveArtifactDir();
  const vkeyPath = path.join(dir, files.vkey);
  if (!fs.existsSync(vkeyPath)) {
    throw new Error(
      `Missing exported verification key: ${vkeyPath}. ` +
        `Run: node scripts/inspect-circuits.mjs`,
    );
  }
  const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
  return snarkjs.groth16.verify(vKey, publicSignals, proof);
}

// ---------------------------------------------------------------------------
// Steal the VFY publicInputsHash (SPEC.md — published, use exactly)
// ---------------------------------------------------------------------------

export type StealAction = "HOLD" | "FORTIFY" | "EXTRACT";

export interface StealPublicInputsHashInput {
  strategyCommitmentHash: string;
  matchId: string;
  turn: number;
  selfBalance: string | number;
  opponentBalance: string | number;
  action: StealAction;
  amount: number;
  circuitVersion?: string;
}

const STEAL_ACTION_CODE: Record<StealAction, number> = {
  HOLD: 0,
  FORTIFY: 1,
  EXTRACT: 2,
};

/** Encode a BigInt as 32-byte big-endian. Throws on negative/overflow. */
function toBytes32BE(value: bigint, field: string): Uint8Array {
  if (value < 0n) throw new Error(`publicInputsHash: ${field} must be >= 0`);
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`publicInputsHash: ${field} exceeds 32 bytes`);
  return out;
}

function parseUintField(value: string | number, field: string): bigint {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`publicInputsHash: ${field} must be an integer`);
    }
    return BigInt(value);
  }
  const s = value.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  throw new Error(`publicInputsHash: ${field} must be a decimal or 0x-hex integer, got ${JSON.stringify(value)}`);
}

/**
 * Compute the Steal the VFY publicInputsHash (SPEC.md, published).
 *
 * keccak256 over 8 fields, each 32-byte big-endian, in this exact order:
 *  1. strategyCommitment.hash (0x-hex, 32 bytes)
 *  2. matchId (hyphens stripped, parsed as an integer)
 *  3. turn
 *  4. selfBalance
 *  5. opponentBalance
 *  6. action (HOLD=0, FORTIFY=1, EXTRACT=2)
 *  7. amount (0 for HOLD/FORTIFY — forced, even if a nonzero amount is passed)
 *  8. circuitVersion "v1" (=1; defaults to "v1" when omitted)
 *
 * Returns "0x..." hex (64 hex chars). Uses @noble/hashes keccak_256.
 */
export function computeStealPublicInputsHash(
  input: StealPublicInputsHashInput,
): string {
  const commitment = parseUintField(input.strategyCommitmentHash, "strategyCommitmentHash");
  const matchId = BigInt("0x" + input.matchId.replace(/-/g, ""));
  const turn = parseUintField(input.turn, "turn");
  const selfBalance = parseUintField(input.selfBalance, "selfBalance");
  const opponentBalance = parseUintField(input.opponentBalance, "opponentBalance");
  const actionCode = STEAL_ACTION_CODE[input.action];
  if (actionCode === undefined) {
    throw new Error(`publicInputsHash: unknown action ${JSON.stringify(input.action)}`);
  }
  // Spec: amount is 0 for HOLD/FORTIFY.
  const amount = input.action === "EXTRACT" ? parseUintField(input.amount, "amount") : 0n;

  const versionStr = input.circuitVersion ?? "v1";
  const versionMatch = /^v(\d+)$/.exec(versionStr.trim());
  const version = versionMatch ? BigInt(versionMatch[1]) : parseUintField(versionStr, "circuitVersion");

  const buf = new Uint8Array(32 * 8);
  const fields: [bigint, string][] = [
    [commitment, "strategyCommitmentHash"],
    [matchId, "matchId"],
    [turn, "turn"],
    [selfBalance, "selfBalance"],
    [opponentBalance, "opponentBalance"],
    [BigInt(actionCode), "action"],
    [amount, "amount"],
    [version, "circuitVersion"],
  ];
  fields.forEach(([value, field], i) => {
    buf.set(toBytes32BE(value, field), i * 32);
  });

  return "0x" + bytesToHex(keccak_256(buf));
}
