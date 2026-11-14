import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createServer } from "../server";
import { signResponse, verifySignature } from "../hmac";
import { loadConfig } from "../config";
import type { AgentConfig } from "../config";

const TEST_SECRET = "test-only-secret-never-real";

const baseConfig: AgentConfig = {
  ...loadConfig({ ALLOW_NO_SECRET: "1" }),
  port: 0,
  host: "127.0.0.1",
  agentName: "muse",
  hmacSecret: TEST_SECRET,
  allowNoSecret: false,
};

let server: ReturnType<typeof createServer>;
let baseUrl: string;

function sign(body: string): string {
  return signResponse(Buffer.from(body), TEST_SECRET);
}

async function post(
  path: string,
  body: unknown,
  opts: { sign?: boolean; tamper?: boolean } = {},
): Promise<Response> {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (opts.sign !== false) {
    headers["x-agent-games-signature"] =
      opts.tamper === true ? sign(raw + "x") : sign(raw);
  }
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    body: raw,
  });
}

const FUTURE = "2099-01-01T00:00:00Z";
const PAST = "2020-01-01T00:00:00Z";

function gatekeeperEnvelope(overrides: Record<string, unknown> = {}) {
  const { input: inputOverrides, ...rest } = overrides as {
    input?: Record<string, unknown>;
    [k: string]: unknown;
  };
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    issued_at: "2026-11-15T00:00:00Z",
    deadline_at: FUTURE,
    input: {
      // Real platform values (the gatekeeper vkHash, a real address):
      // the suite exercises the REAL proving path, not the degraded one.
      registered_vk:
        "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk:
        "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      condition_recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xservertx1",
      ...inputOverrides,
    },
    ...rest,
  };
}

function stealEnvelope(
  matchId: string,
  turn: number,
  me: number,
  opponent: number,
  nonce: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId,
    turn,
    issuedAt: "2026-11-15T00:00:00Z",
    deadlineAt: FUTURE,
    state: {
      selfBalance: String(me),
      opponentBalance: String(opponent),
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: "0x" + "11".repeat(32) }, // valid 32-byte hex
    resolverVersion: "v1",
    nonce,
    ...overrides,
  };
}

describe("server", () => {
  before(async () => {
    server = createServer(baseConfig);
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  // snarkjs/ffjavascript spawn a worker-thread pool during proving that
  // never terminates (see src/tests/proving.test.ts): a test child that
  // proved anything never exits by itself, so the runner hangs after the
  // suite finishes. Exit explicitly. The server is unaffected (long-lived;
  // workers are reused across proofs).
  after(() => {
    setTimeout(() => process.exit(0), 300);
  });

  it("GET /health returns 200 {status:ok, agent, tracks}", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.status, "ok");
    assert.equal(body.agent, "muse");
    assert.ok(Array.isArray(body.tracks));
  });

  it("preflight: signed → 200 {ok:true, protocolVersion:v1} + signature", async () => {
    const res = await post("/agent", {
      type: "agent-games.preflight.v1",
      agent_id: "agt_test123",
      issued_at: "2026-11-15T00:00:00Z",
      nonce: "abc123",
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.ok, true);
    assert.equal(body.protocolVersion, "v1");
    const sig = res.headers.get("x-agent-games-signature");
    assert.ok(sig && sig.length > 0);
  });

  it("preflight without signature → 401", async () => {
    const res = await post(
      "/agent",
      {
        type: "agent-games.preflight.v1",
        agent_id: "agt_test123",
        issued_at: "2026-11-15T00:00:00Z",
        nonce: "abc123",
      },
      { sign: false },
    );
    assert.equal(res.status, 401);
  });

  it("POST /agent without signature → 401", async () => {
    const res = await post("/agent", gatekeeperEnvelope(), { sign: false });
    assert.equal(res.status, 401);
  });

  it("POST /agent with tampered body → 401", async () => {
    const res = await post("/agent", gatekeeperEnvelope(), { tamper: true });
    assert.equal(res.status, 401);
  });

  it("POST /agent with wrong-secret signature → 401", async () => {
    const raw = JSON.stringify(gatekeeperEnvelope());
    const res = await fetch(`${baseUrl}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": signResponse(
          Buffer.from(raw),
          "wrong-secret",
        ),
      },
      body: raw,
    });
    assert.equal(res.status, 401);
  });

  it("valid signed gatekeeper envelope → 200 with decision", async () => {
    const res = await post(
      "/agent",
      gatekeeperEnvelope({ task_id: "gk_valid_1" }),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.decision, "APPROVE");
    assert.equal(body.reason_code, "VALID_CONDITION");
    // Proving works (gatekeeper inputs recovered — see PROBE.md): a REAL
    // Groth16 proof is attached, 13 public signals, decision signal
    // (index 11) == "1". Never assert proof:null for a valid envelope —
    // that would hide a proving regression.
    assert.notEqual(body.proof, null);
    assert.ok(Array.isArray(body.public_signals));
    const signals = body.public_signals as string[];
    assert.equal(signals.length, 13);
    assert.equal(signals[11], "1");
    assert.equal(body.proof_tx, null); // no KURIER_API_KEY in tests
    assert.match(String(body.proof_status), /Kurier not configured/);
    // Response is signed.
    const sig = res.headers.get("x-agent-games-signature");
    assert.ok(sig && sig.length > 0);
  });

  it("signed gatekeeper REJECT (VK substitution) → 200 REJECT + real proof", async () => {
    const res = await post(
      "/agent",
      gatekeeperEnvelope({
        task_id: "gk_reject_1",
        // A different but VALID hex vk (the vfyPolicy vkHash): the circuit
        // evaluates the VK check as false, so decision 0 verifies.
        input: {
          proof_vk:
            "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
          proof_tx: "0xservertx2",
        },
      }),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.decision, "REJECT");
    assert.equal(body.reason_code, "VK_SUBSTITUTION");
    assert.notEqual(body.proof, null);
    const signals = body.public_signals as string[];
    assert.equal(signals.length, 13);
    assert.equal(signals[11], "0");
  });

  it("same proof_tx, different task → second is PROOF_REUSED", async () => {
    const first = await post(
      "/agent",
      gatekeeperEnvelope({
        task_id: "gk_reuse_1",
        input: { proof_tx: "0xservertx3" },
      }),
    );
    assert.equal(
      ((await first.json()) as Record<string, unknown>).decision,
      "APPROVE",
    );
    const second = await post(
      "/agent",
      gatekeeperEnvelope({
        task_id: "gk_reuse_2",
        input: { proof_tx: "0xservertx3" },
      }),
    );
    const body2 = (await second.json()) as Record<string, unknown>;
    assert.equal(body2.decision, "REJECT");
    assert.equal(body2.reason_code, "PROOF_REUSED");
    // PROOF_REUSED is an off-circuit reject: no witness exists for it
    // (the circuit asserts decision == its evaluation, and all five
    // on-circuit conditions hold for a reused proof) — see src/server.ts.
    // The decision is returned WITHOUT a proof, honestly.
    assert.equal(body2.proof, null);
    assert.match(
      String(body2.proof_status),
      /no proof exists for PROOF_REUSED/,
    );
  });

  it("task_id resend returns the SAME decision (no double-record)", async () => {
    const env = gatekeeperEnvelope({
      task_id: "gk_resend_1",
      input: { proof_tx: "0xservertx4" },
    });
    const first = await post("/agent", env);
    const b1 = (await first.json()) as Record<string, unknown>;
    assert.equal(b1.decision, "APPROVE");
    const second = await post("/agent", env);
    const b2 = (await second.json()) as Record<string, unknown>;
    assert.equal(b2.decision, "APPROVE");
    assert.equal(b2.reason_code, "VALID_CONDITION");
  });

  it("gatekeeper with past deadline_at → REJECT EXPIRED_CONDITION", async () => {
    const res = await post(
      "/agent",
      gatekeeperEnvelope({ task_id: "gk_deadline_1", deadline_at: PAST }),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.decision, "REJECT");
    assert.equal(body.reason_code, "EXPIRED_CONDITION");
  });

  it("response x-agent-games-signature verifies over the raw body", async () => {
    const res = await post(
      "/agent",
      gatekeeperEnvelope({
        task_id: "gk_sigcheck",
        input: { proof_tx: "0xservertx5" },
      }),
    );
    const rawText = await res.text();
    const sig = res.headers.get("x-agent-games-signature");
    assert.ok(sig);
    assert.equal(
      verifySignature(Buffer.from(rawText), sig, TEST_SECRET),
      true,
    );
  });

  it("unknown track → 400", async () => {
    const res = await post("/agent", { type: "agent-games.unknown.v9" });
    assert.equal(res.status, 400);
  });

  it("explicit /agent/gatekeeper path works", async () => {
    const res = await post(
      "/agent/gatekeeper",
      gatekeeperEnvelope({
        task_id: "gk_explicit",
        input: { proof_tx: "0xservertx6" },
      }),
    );
    assert.equal(res.status, 200);
    assert.equal(
      ((await res.json()) as Record<string, unknown>).decision,
      "APPROVE",
    );
  });

  it("steal turn 0 → 200 with exact response shape", async () => {
    const res = await post(
      "/agent/steal",
      stealEnvelope(
        "9f4e1b2a-1111-4222-8333-444455556666",
        0,
        100,
        100,
        "n-m1-0",
      ),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.matchId, "9f4e1b2a-1111-4222-8333-444455556666");
    assert.equal(body.turn, 0);
    const action = body.action as Record<string, unknown>;
    assert.equal(action.type, "EXTRACT");
    assert.equal(action.amount, 10); // number, not string
    const policyProof = body.policyProof as Record<string, unknown>;
    assert.equal(policyProof.circuitVersion, "v1");
    // computeStealPublicInputsHash is implemented (SPEC.md, exact
    // keccak256): a valid 0x + 64-hex hash is attached.
    assert.match(
      String(policyProof.publicInputsHash),
      /^0x[0-9a-f]{64}$/,
    );
    assert.equal(typeof body.agentTimestamp, "string");
    assert.match(
      String(body.idempotencyKey),
      /^9f4e1b2a-1111-4222-8333-444455556666:0:/,
    );
    assert.equal(body.proof, null);
    assert.match(String(body.proof_status), /proving failed/);
  });

  it("steal turn 1 advances with a fresh idempotencyKey", async () => {
    const first = await post(
      "/agent/steal",
      stealEnvelope(
        "9f4e1b2a-2222-4222-8333-444455556666",
        0,
        100,
        100,
        "n-m2-0",
      ),
    );
    const b1 = (await first.json()) as Record<string, unknown>;
    // After EXTRACT 10: me 110, opponent 90.
    const second = await post(
      "/agent/steal",
      stealEnvelope(
        "9f4e1b2a-2222-4222-8333-444455556666",
        1,
        110,
        90,
        "n-m2-1",
      ),
    );
    assert.equal(second.status, 200);
    const b2 = (await second.json()) as Record<string, unknown>;
    assert.equal(b2.turn, 1);
    assert.equal(
      (b2.action as Record<string, unknown>).type,
      "EXTRACT",
    );
    assert.equal((b2.action as Record<string, unknown>).amount, 9);
    assert.notEqual(b2.idempotencyKey, b1.idempotencyKey);
  });

  it("steal replay of the same turn → HOLD (stale turn)", async () => {
    const res = await post(
      "/agent/steal",
      stealEnvelope(
        "9f4e1b2a-2222-4222-8333-444455556666",
        1,
        119,
        81,
        "n-m2-1-replay",
      ),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(
      (body.action as Record<string, unknown>).type,
      "HOLD",
    );
    assert.match(String(body.proof_status), /stale turn/);
  });

  it("steal with past deadlineAt → HOLD with no proof", async () => {
    const res = await post(
      "/agent/steal",
      stealEnvelope(
        "9f4e1b2a-3333-4222-8333-444455556666",
        0,
        100,
        100,
        "n-m3-0",
        {
          deadlineAt: PAST,
        },
      ),
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(
      (body.action as Record<string, unknown>).type,
      "HOLD",
    );
    assert.equal(body.proof, null);
    assert.match(String(body.proof_status), /deadlineAt/);
  });
});
