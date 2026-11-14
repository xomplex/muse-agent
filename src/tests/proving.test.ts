/**
 * proving.test.ts — tests for src/proving.ts (Groth16 proving + Steal hash).
 *
 * Run via `npm test` (builds first, then node --test dist/tests/).
 * The gatekeeper round-trip tests run REAL fullProve + local verify against
 * the official platform artifacts — no fake proofs anywhere.
 */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { after, describe, it } from "node:test";
import {
  GATEKEEPER_INPUT_NAMES,
  PUBLISHED_VK_HASH,
  buildGatekeeperCircuitInputs,
  computeStealPublicInputsHash,
  generateProof,
  publishedVkHash,
  resolveArtifactDir,
  verifyProofLocally,
} from "../proving.js";

// snarkjs/ffjavascript spawn a worker-thread pool during proving
// (taskmanager.js / threadman.js) and never terminate it, so a process that
// proved anything never exits by itself (verified: 4 dangling MessagePorts
// after one fullProve; unref() alone does not help — the Worker objects
// stay referenced). The server is unaffected (long-lived; workers are
// reused across proofs), but a one-shot test child must exit explicitly.
// The 300 ms delay lets TAP output flush; failure reporting is unaffected
// (verified: the runner still exits 1 when a test fails).
after(() => {
  setTimeout(() => process.exit(0), 300);
});

const ART = resolveArtifactDir();

const EXPECTED_SIZES: Record<string, number> = {
  "gatekeeper.wasm": 1755820,
  "gatekeeper_final.zkey": 309750,
  "vfy-policy.wasm": 2991212,
  "vfy-policy_final.zkey": 810586,
};

/** All-conditions-true gatekeeper assignment (SPEC.md example values). */
const APPROVE_INPUTS: Record<string, string> = {
  registeredVkHash: "12345",
  proofVkHash: "12345",
  minimum: "1000",
  publicBalance: "1460",
  expiryBlock: "8430000",
  currentBlock: "8420000",
  recipient: "123456789",
  conditionRecipient: "123456789",
  amount: "500",
  maxTransfer: "1000",
  decision: "1",
  taskId: "1",
  salt: "7",
};

describe("circuit artifacts on disk", () => {
  it("all four official artifacts exist with the published sizes", () => {
    for (const [name, size] of Object.entries(EXPECTED_SIZES)) {
      const p = path.join(ART, name);
      assert.ok(fs.existsSync(p), `missing artifact: ${name}`);
      assert.equal(fs.statSync(p).size, size, `${name} size mismatch (corrupt?)`);
    }
    assert.ok(fs.existsSync(path.join(ART, "circuit-info.json")));
  });

  it("CHECKSUMS.txt verifies (sha256s recorded at download time)", () => {
    assert.ok(fs.existsSync(path.join(ART, "CHECKSUMS.txt")));
    // Sizes are checked above; the checksum file itself must list all files.
    const txt = fs.readFileSync(path.join(ART, "CHECKSUMS.txt"), "utf8");
    for (const name of Object.keys(EXPECTED_SIZES)) assert.ok(txt.includes(name), `CHECKSUMS.txt missing ${name}`);
  });

  it("exported VKs have the expected public-input counts", () => {
    for (const [file, nPublic] of [
      ["gatekeeper.vkey.json", 13],
      ["vfy-policy.vkey.json", 9],
    ] as const) {
      const vk = JSON.parse(fs.readFileSync(path.join(ART, file), "utf8"));
      assert.equal(vk.protocol, "groth16");
      assert.equal(vk.curve, "bn128");
      assert.equal(vk.IC.length - 1, nPublic, `${file} public-input count`);
    }
  });

  it("published vkHashes match circuit-info.json", () => {
    assert.equal(publishedVkHash("gatekeeper"), PUBLISHED_VK_HASH.gatekeeper);
    assert.equal(publishedVkHash("vfyPolicy"), PUBLISHED_VK_HASH.vfyPolicy);
    const info = JSON.parse(fs.readFileSync(path.join(ART, "circuit-info.json"), "utf8"));
    assert.equal(info.circuits.gatekeeper.vkHash, PUBLISHED_VK_HASH.gatekeeper);
    assert.equal(info.circuits.vfyPolicy.vkHash, PUBLISHED_VK_HASH.vfyPolicy);
  });
});

describe("input-name recovery (PROBE.md)", () => {
  it("gatekeeper: all 13 input names recovered", () => {
    assert.equal(GATEKEEPER_INPUT_NAMES.length, 13);
    const probe = fs.readFileSync(path.join(ART, "PROBE.md"), "utf8");
    assert.match(probe, /COMPLETE/);
    for (const name of GATEKEEPER_INPUT_NAMES) {
      assert.ok(probe.includes(name), `PROBE.md missing recovered name ${name}`);
    }
  });

  it("vfyPolicy: recovery is documented as INCOMPLETE (9/17)", () => {
    const probe = fs.readFileSync(path.join(ART, "PROBE.md"), "utf8");
    assert.match(probe, /vfyPolicy/);
    assert.match(probe, /INCOMPLETE/);
  });
});

describe("buildGatekeeperCircuitInputs (translator)", () => {
  const ENVELOPE = {
    registered_vk: "0x" + "ab".repeat(32),
    proof_vk: "0x" + "ab".repeat(32),
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    condition_recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xdeadbeef",
    task_id: "gk_24_9d1",
  };

  it("translates envelope names to the 13 circuit names, drops proof_tx", () => {
    const out = buildGatekeeperCircuitInputs(ENVELOPE);
    assert.deepEqual(Object.keys(out).sort(), [...GATEKEEPER_INPUT_NAMES].sort());
    assert.equal(out.registeredVkHash, out.proofVkHash);
    assert.equal(out.registeredVkHash, BigInt("0x" + "ab".repeat(32)).toString());
    assert.equal(out.recipient, BigInt("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").toString());
    assert.equal(out.publicBalance, "1460");
    assert.equal(out.expiryBlock, "8430000");
    assert.equal(out.decision, "1", "all conditions hold -> derived APPROVE");
  });

  it("encodes alphanumeric taskId as UTF-8 byte integer", () => {
    const out = buildGatekeeperCircuitInputs(ENVELOPE);
    assert.equal(
      out.taskId,
      BigInt("0x" + Buffer.from("gk_24_9d1", "utf8").toString("hex")).toString(),
    );
    assert.equal(buildGatekeeperCircuitInputs({ ...ENVELOPE, task_id: "42" }).taskId, "42");
  });

  it("derives decision=0 when a condition fails", () => {
    assert.equal(buildGatekeeperCircuitInputs({ ...ENVELOPE, amount: "1500" }).decision, "0");
    assert.equal(
      buildGatekeeperCircuitInputs({ ...ENVELOPE, proof_vk: "0x" + "cd".repeat(32) }).decision,
      "0",
    );
  });

  it("explicit decision wins over derivation", () => {
    assert.equal(buildGatekeeperCircuitInputs({ ...ENVELOPE, decision: "REJECT" }).decision, "0");
    assert.equal(buildGatekeeperCircuitInputs({ ...ENVELOPE, amount: "1500", decision: "APPROVE" }).decision, "1");
  });

  it("draws a fresh random salt per call unless supplied", () => {
    const a = buildGatekeeperCircuitInputs(ENVELOPE);
    const b = buildGatekeeperCircuitInputs(ENVELOPE);
    assert.notEqual(a.salt, b.salt, "random salt must differ per proof");
    assert.equal(buildGatekeeperCircuitInputs({ ...ENVELOPE, salt: "7" }).salt, "7");
  });

  it("lists missing required fields instead of failing cryptically", () => {
    assert.throws(() => buildGatekeeperCircuitInputs({ minimum: "1" }), /missing required field.*registeredVkHash/);
  });
});

describe("computeStealPublicInputsHash", () => {
  const BASE = {
    strategyCommitmentHash: "0x" + "11".repeat(32),
    matchId: "9f4e1b2a-1111-2222-3333-444455556666",
    turn: 3,
    selfBalance: "95",
    opponentBalance: "105",
    action: "EXTRACT" as const,
    amount: 5,
  };

  it("is deterministic and returns 0x + 64 hex chars", () => {
    const a = computeStealPublicInputsHash(BASE);
    const b = computeStealPublicInputsHash(BASE);
    assert.equal(a, b);
    assert.match(a, /^0x[0-9a-f]{64}$/);
  });

  it("matches independent keccak256 reference vectors (pycryptodome)", () => {
    // Vector B: realistic EXTRACT turn.
    assert.equal(
      computeStealPublicInputsHash(BASE),
      "0xe22245b85829885591b16993469bd701aaa4b50de89f00e475808bd7561f1879",
    );
    // Vector C: same fields but HOLD (action 0, amount forced 0).
    assert.equal(
      computeStealPublicInputsHash({ ...BASE, action: "HOLD", amount: 5 }),
      "0x88826ee40e3f13e55837a979a22c33be6822ee11edec9429c91abfd6b2c17b58",
    );
    // Vector A: all fields zero except circuitVersion=1.
    assert.equal(
      computeStealPublicInputsHash({
        strategyCommitmentHash: "0x" + "00".repeat(32),
        matchId: "00000000-0000-0000-0000-000000000000",
        turn: 0,
        selfBalance: "0",
        opponentBalance: "0",
        action: "HOLD",
        amount: 0,
      }),
      "0x11934057fe979f7d236d4bfe0cfcb7b2b1d5f4145867576ef0d8026fdcb33ab0",
    );
  });

  it("action enum maps HOLD/FORTIFY/EXTRACT to different hashes", () => {
    const hold = computeStealPublicInputsHash({ ...BASE, action: "HOLD", amount: 0 });
    const fortify = computeStealPublicInputsHash({ ...BASE, action: "FORTIFY", amount: 0 });
    const extract = computeStealPublicInputsHash(BASE);
    assert.notEqual(hold, fortify);
    assert.notEqual(hold, extract);
    assert.notEqual(fortify, extract);
  });

  it("amount is forced to 0 for HOLD/FORTIFY", () => {
    const hold0 = computeStealPublicInputsHash({ ...BASE, action: "HOLD", amount: 0 });
    const hold5 = computeStealPublicInputsHash({ ...BASE, action: "HOLD", amount: 5 });
    assert.equal(hold5, hold0);
    const fort0 = computeStealPublicInputsHash({ ...BASE, action: "FORTIFY", amount: 0 });
    const fort9 = computeStealPublicInputsHash({ ...BASE, action: "FORTIFY", amount: 9 });
    assert.equal(fort9, fort0);
  });

  it("changing turn or balances changes the hash", () => {
    const h = computeStealPublicInputsHash(BASE);
    assert.notEqual(computeStealPublicInputsHash({ ...BASE, turn: 4 }), h);
    assert.notEqual(computeStealPublicInputsHash({ ...BASE, selfBalance: "96" }), h);
  });
});

describe("generateProof — gatekeeper (REAL fullProve + verify)", () => {
  it("round-trips: all-conditions-true + decision=1 verifies locally", async () => {
    const res = await generateProof({
      track: "gatekeeper",
      circuitInputs: APPROVE_INPUTS,
      publicInputs: [],
    });
    assert.equal(res.placeholder, false);
    assert.equal(res.circuit, "gatekeeper");
    assert.equal(res.circuitVersion, PUBLISHED_VK_HASH.gatekeeper);
    assert.equal(res.publicSignals.length, 13);
    // Public-signal order (verified live): [Poseidon(salt,taskId),
    // registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
    // currentBlock, recipient, conditionRecipient, amount, maxTransfer,
    // decision, taskId]
    assert.deepEqual(res.publicSignals.slice(1), [
      "12345", "12345", "1000", "1460", "8430000", "8420000",
      "123456789", "123456789", "500", "1000", "1", "1",
    ]);
    assert.equal(
      res.publicSignals[0],
      "15805707659607764519661337093514215866263235633300838807773375348842636740",
      "signal[0] must be Poseidon(salt=7, taskId=1)",
    );
    assert.equal(await verifyProofLocally(res.proof, res.publicSignals, "gatekeeper"), true);
  });

  it("REJECT path: violated condition + decision=0 verifies locally", async () => {
    const res = await generateProof({
      track: "gatekeeper",
      circuitInputs: { ...APPROVE_INPUTS, amount: "1500", decision: "0" },
      publicInputs: [],
    });
    assert.equal(res.publicSignals[11], "0");
    assert.equal(await verifyProofLocally(res.proof, res.publicSignals, "gatekeeper"), true);
  });

  it("wrong decision cannot produce a proof (circuit asserts decision)", async () => {
    await assert.rejects(
      () =>
        generateProof({
          track: "gatekeeper",
          circuitInputs: { ...APPROVE_INPUTS, amount: "1500", decision: "1" },
          publicInputs: [],
        }),
      /Assert Failed/,
    );
  });

  it("tampered publicSignals FAIL local verification", async () => {
    const res = await generateProof({
      track: "gatekeeper",
      circuitInputs: APPROVE_INPUTS,
      publicInputs: [],
    });
    assert.equal(await verifyProofLocally(res.proof, res.publicSignals, "gatekeeper"), true);
    const tampered = [...res.publicSignals];
    tampered[9] = "501"; // amount 500 -> 501
    assert.equal(await verifyProofLocally(res.proof, tampered, "gatekeeper"), false);
  });

  it("unknown / missing inputs throw a clear error listing what's missing (no fake proof)", async () => {
    await assert.rejects(
      () =>
        generateProof({
          track: "gatekeeper",
          circuitInputs: { not_a_signal: "1" },
          publicInputs: [],
        }),
      /missing required field/,
    );
  });

  it("envelope-style inputs translate and prove (server call shape)", async () => {
    // Exactly what src/server.ts passes: raw envelope fields + task_id.
    const res = await generateProof({
      track: "gatekeeper",
      circuitInputs: {
        registered_vk: "0x" + "ab".repeat(32),
        proof_vk: "0x" + "ab".repeat(32),
        minimum: "1000",
        public_balance: "1460",
        expiry_block: 8430000,
        current_block: 8420000,
        recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        condition_recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        amount: "500",
        max_transfer: "1000",
        proof_tx: "0xdeadbeef",
        task_id: "gk_24_9d1",
        // no decision passed -> derived (all conditions hold -> APPROVE=1)
        // no salt passed -> random blinding drawn per proof
      },
      publicInputs: [],
    });
    assert.equal(res.publicSignals.length, 13);
    assert.equal(res.publicSignals[11], "1", "derived decision must be APPROVE");
    // taskId signal = big-endian integer of UTF-8 bytes "gk_24_9d1"
    const expectedTaskId = BigInt("0x" + Buffer.from("gk_24_9d1", "utf8").toString("hex")).toString();
    assert.equal(res.publicSignals[12], expectedTaskId);
    assert.equal(await verifyProofLocally(res.proof, res.publicSignals, "gatekeeper"), true);
  });

  it("envelope-style REJECT: explicit decision=REJECT is respected even when conditions hold", async () => {
    // The server's decision wins over derivation (e.g. PROOF_REUSED).
    // NOTE: a REJECT decision with all conditions true FAILS the circuit
    // assert (decision must equal the evaluated condition), so this must
    // throw — the server must not request a proof for a decision the
    // circuit disagrees with. The honest behaviour is a loud error.
    await assert.rejects(
      () =>
        generateProof({
          track: "gatekeeper",
          circuitInputs: { ...APPROVE_INPUTS, decision: "REJECT" },
          publicInputs: [],
        }),
      /Assert Failed/,
    );
  });
});

describe("generateProof — steal (honest failure)", () => {
  it("throws a clear error: vfyPolicy inputs are not fully published", async () => {
    await assert.rejects(
      () =>
        generateProof({ track: "steal", circuitInputs: {}, publicInputs: [] }),
      /not fully published/,
    );
  });
});
