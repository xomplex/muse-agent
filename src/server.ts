/**
 * HTTP server for the Agent Games agent "muse" — plain node:http, no framework.
 *
 * Request flow (ARCHITECTURE.md):
 *   1. Capture the RAW body (never parse before HMAC).
 *   2. HMAC-gate every POST: header `x-agent-games-signature`,
 *      HMAC-SHA256 hex over the raw body, secret `AGENT_GAMES_HMAC_SECRET`.
 *      Missing/invalid signature → 401, no decision.
 *   3. Route by path / envelope type; fail closed on anything unknown.
 *   4. Every handler runs inside the response-timeout budget (default
 *      55 s) so the platform's 60 s hard deadline is never breached;
 *      on timeout → 503 {error:"timeout"}.
 *   5. Every response is signed with `x-agent-games-signature` over the
 *      raw response body (SPEC.md).
 *
 * Preflight (`agent-games.preflight.v1`) is answered after the same HMAC
 * check with {"ok":true,"protocolVersion":"v1"}.
 *
 * Gatekeeper `task_id` is the idempotency key (SPEC.md): decisions are
 * cached by task_id in memory, so a platform resend returns the SAME
 * decision and never double-records the proof_tx.
 *
 * Inbound `deadline_at` (gatekeeper) / `deadlineAt` (steal) is a hard
 * deadline: if the current time is already past it when the request
 * arrives, fail closed (REJECT EXPIRED_CONDITION / HOLD with no proof).
 *
 * Proving is an optional module owned by another builder (src/proving.ts).
 * It is loaded with a dynamic import; if the module (or the
 * computeStealPublicInputsHash function) is absent or fails, the server
 * takes the documented DEGRADED path: decision/move is still returned,
 * but proof / publicInputsHash are omitted and `proof_status` explains
 * why. A proof, a proof_tx, and a publicInputsHash are NEVER faked.
 *
 * Standalone: `node dist/server.js`. Testable: `createServer(config)`.
 */
import http from "node:http";
import crypto from "node:crypto";
import { loadConfig, type AgentConfig } from "./config";
import {
  verifySignature,
  signResponse,
  RESPONSE_SIGNATURE_HEADER,
} from "./hmac";
import { decideGatekeeper } from "./gatekeeper";
import {
  createMatch,
  policyMove,
  validateTurn,
  applyMove,
  syncFortification,
  ACTION_HOLD,
} from "./steal";
import { submitProof, KurierNotConfiguredError } from "./kurier";
import type {
  GatekeeperEnvelope,
  GatekeeperResponse,
  StealEnvelope,
  StealResponse,
  GenerateProofRequest,
  GenerateProofResult,
  StealPublicInputsHashRequest,
  PreflightResponse,
} from "./types";

export const TRACK_GATEKEEPER = "agent-games.proof-gatekeeper.v1";
export const TRACK_PREFLIGHT = "agent-games.preflight.v1";
/** Steal policyProof circuitVersion (exact per SPEC.md). */
export const STEAL_CIRCUIT_VERSION = "v1" as const;

const MAX_BODY_BYTES = 1_000_000;

interface ProvingModule {
  generateProof: (
    req: GenerateProofRequest,
  ) => Promise<GenerateProofResult>;
  computeStealPublicInputsHash?: (
    req: StealPublicInputsHashRequest,
  ) => string;
}

/** Lazily loaded proving module (owned by another builder). */
let provingModule: ProvingModule | null | undefined;
async function loadProving(): Promise<ProvingModule | null> {
  if (provingModule !== undefined) return provingModule;
  try {
    // Dynamic import: the file may not exist yet (another builder owns it).
    const mod = (await import("./proving")) as ProvingModule;
    if (typeof mod.generateProof !== "function") {
      provingModule = null;
      return null;
    }
    provingModule = mod;
    return mod;
  } catch {
    provingModule = null;
    return null;
  }
}

/** Local fallback commitment when STRATEGY_COMMITMENT is unset. */
function localPolicyCommitment(): string {
  return crypto
    .createHash("sha256")
    .update("muse-steal-policy-v1:extract-min(10,floor(opp*0.10));fortify-2-when-behind;hold")
    .digest("hex");
}

interface ServerState {
  config: AgentConfig;
  seenProofTxs: Set<string>;
  /** task_id → decision, so resends return the same decision. */
  decisionCache: Map<string, GatekeeperResponse>;
  matches: Map<string, import("./steal").MatchState>;
  policyCommitment: string;
}

/** Parse an ISO deadline string; null when absent/unparseable. */
function parseDeadline(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  secret: string | undefined,
  algorithm: string,
): void {
  const raw = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": raw.length,
    ...(secret
      ? {
          [RESPONSE_SIGNATURE_HEADER]: signResponse(
            raw,
            secret,
            algorithm,
          ),
        }
      : {}),
  });
  res.end(raw);
}

function isRecord<T>(v: unknown): v is Record<string, T> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validGatekeeperEnvelope(
  body: unknown,
): body is GatekeeperEnvelope {
  if (!isRecord(body)) return false;
  if (body.type !== TRACK_GATEKEEPER) return false;
  if (typeof body.task_id !== "string") return false;
  const input = body.input;
  if (!isRecord(input)) return false;
  const required = [
    "registered_vk",
    "proof_vk",
    "minimum",
    "public_balance",
    "expiry_block",
    "current_block",
    "recipient",
    "condition_recipient",
    "amount",
    "max_transfer",
    "proof_tx",
  ];
  return required.every((k) => input[k] !== undefined);
}

function validStealEnvelope(body: unknown): body is StealEnvelope {
  if (!isRecord(body)) return false;
  if (typeof body.matchId !== "string" || body.matchId.length === 0)
    return false;
  if (typeof body.turn !== "number") return false;
  if (typeof body.nonce !== "string" || body.nonce.length === 0)
    return false;
  if (!isRecord(body.state)) return false;
  if (
    typeof body.state.selfBalance !== "string" ||
    typeof body.state.opponentBalance !== "string"
  )
    return false;
  if (!isRecord(body.strategyCommitment)) return false;
  if (typeof body.strategyCommitment.hash !== "string") return false;
  return true;
}

function stealHoldResponse(
  envelope: StealEnvelope,
  proofStatus: string,
): StealResponse {
  return {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: { type: ACTION_HOLD },
    policyProof: { circuitVersion: STEAL_CIRCUIT_VERSION },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: `${envelope.matchId}:${envelope.turn}:${crypto.randomUUID()}`,
    proof: null,
    public_signals: [],
    proof_status: proofStatus,
  };
}

async function handleGatekeeper(
  envelope: GatekeeperEnvelope,
  state: ServerState,
): Promise<GatekeeperResponse> {
  // Idempotency: a platform resend returns the cached decision.
  const cached = state.decisionCache.get(envelope.task_id);
  if (cached) return { ...cached };

  let response: GatekeeperResponse;

  // Hard deadline: already past deadline_at when the request arrives.
  const deadline = parseDeadline(envelope.deadline_at);
  if (deadline !== null && Date.now() > deadline) {
    response = {
      decision: "REJECT",
      reason_code: "EXPIRED_CONDITION",
      proof_tx: null,
      proof: null,
      proof_status: "deadline_at already passed on arrival",
    };
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  const decision = decideGatekeeper(envelope.input, {
    registeredVk: envelope.input.registered_vk,
    seenProofTxs: state.seenProofTxs,
    nowBlock: envelope.input.current_block,
  });
  // Record proof_tx immediately after the decision is computed, for
  // both APPROVE and REJECT, so the same proof is never decided twice.
  if (envelope.input.proof_tx) {
    state.seenProofTxs.add(envelope.input.proof_tx);
  }

  response = {
    decision: decision.decision,
    reason_code: decision.reason_code,
    proof_tx: null,
  };

  // PROOF_REUSED is an OFF-CIRCUIT reject: the circuit evaluates only the
  // five on-circuit conditions and asserts decision == its evaluation
  // (GatekeeperEvaluation_79 line 102). For a reused proof all five
  // conditions hold, so the circuit's evaluation is APPROVE — no witness
  // exists for decision=REJECT, and a proof of decision=APPROVE would
  // contradict the server's own REJECT. Do not attempt proving here:
  // return the REJECT with no proof and say why. (The decision itself is
  // what the platform scores; a missing proof on this one reason code is
  // the platform's own design, not a failure of this agent.)
  if (decision.reason_code === "PROOF_REUSED") {
    response.proof = null;
    response.proof_status =
      "no proof exists for PROOF_REUSED: the gatekeeper circuit asserts " +
      "decision == its evaluated condition, and all five on-circuit " +
      "conditions hold for a reused proof — a REJECT proof cannot be " +
      "generated, so the decision is returned without a proof";
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  const proving = await loadProving();
  if (!proving) {
    response.proof = null;
    response.proof_status = "proving module missing";
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  let proof: GenerateProofResult;
  try {
    // Circuit inputs are the 13 recovered gatekeeper names (see
    // src/proving.ts / circuits/artifacts/PROBE.md). The server's decision
    // is passed EXPLICITLY — the translator can derive it from the five
    // on-circuit conditions, but derivation cannot see off-circuit rejects
    // (e.g. PROOF_REUSED), and the circuit asserts decision == evaluated
    // condition, so a derived APPROVE on a REJECT task would fail proving.
    proof = await proving.generateProof({
      track: "gatekeeper",
      circuitInputs: {
        ...envelope.input,
        task_id: envelope.task_id,
        decision: decision.decision,
      },
      publicInputs: [
        envelope.input.registered_vk,
        envelope.input.proof_vk,
        envelope.input.minimum,
        envelope.input.public_balance,
        String(envelope.input.expiry_block),
        String(envelope.input.current_block),
        envelope.input.recipient,
        envelope.input.condition_recipient,
        envelope.input.amount,
        envelope.input.max_transfer,
        envelope.input.proof_tx,
      ],
    });
  } catch (err) {
    response.proof = null;
    response.proof_status = `proving failed: ${
      err instanceof Error ? err.message : String(err)
    }`;
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  response.proof = proof.proof;
  response.public_signals = proof.publicSignals;
  if (proof.placeholder) {
    response.proof_status =
      "placeholder proof (local circuit, not the platform circuit) — not submitted to Kurier";
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  if (!state.config.kurierApiKey) {
    response.proof_status =
      "proof generated; Kurier not configured (no KURIER_API_KEY), proof_tx unavailable";
    state.decisionCache.set(envelope.task_id, response);
    return { ...response };
  }

  try {
    const submitted = await submitProof(
      {
        proof: proof.proof,
        publicSignals: proof.publicSignals,
        vkHash: state.config.platformVkHashGatekeeper,
        circuitVersion: proof.circuitVersion,
      },
      {
        apiKey: state.config.kurierApiKey,
        apiUrl: state.config.kurierApiUrl,
        statusPath: state.config.kurierStatusPath,
      },
    );
    response.proof_tx = submitted.proofTx;
    response.proof_status =
      submitted.status === "Finalized"
        ? "finalized"
        : `kurier status: ${submitted.status}`;
  } catch (err) {
    if (err instanceof KurierNotConfiguredError) {
      response.proof_status = "Kurier not configured";
    } else {
      response.proof_status = `kurier submission failed: ${
        err instanceof Error ? err.message : String(err)
      }`;
    }
  }
  state.decisionCache.set(envelope.task_id, response);
  return { ...response };
}

async function handleSteal(
  envelope: StealEnvelope,
  state: ServerState,
): Promise<StealResponse> {
  // Hard deadline: already past deadlineAt when the request arrives.
  const deadline = parseDeadline(envelope.deadlineAt);
  if (deadline !== null && Date.now() > deadline) {
    return stealHoldResponse(envelope, "deadlineAt already passed on arrival");
  }

  let match = state.matches.get(envelope.matchId);
  if (!match) {
    if (envelope.turn !== 0) {
      // Unknown match, not turn 0: fail closed with a HOLD.
      return stealHoldResponse(
        envelope,
        "unknown match (no state for this matchId)",
      );
    }
    match = createMatch(
      envelope.matchId,
      envelope.strategyCommitment.hash,
    );
    state.matches.set(envelope.matchId, match);
  }

  const validation = validateTurn(envelope, match);
  if (!validation.ok) {
    return stealHoldResponse(
      envelope,
      `turn rejected: ${validation.reason}`,
    );
  }

  // Sync platform-authoritative fortification fields, then decide.
  match = syncFortification(
    match,
    envelope.state.selfFortifiedUntilTurn ?? null,
    envelope.state.opponentFortifiedUntilTurn ?? null,
  );
  state.matches.set(envelope.matchId, match);

  const action = policyMove(match);
  const idempotencyKey = `${envelope.matchId}:${envelope.turn}:${crypto.randomUUID()}`;
  const applied = applyMove(match, action, envelope.nonce, idempotencyKey);
  if (!applied.ok) {
    return stealHoldResponse(
      envelope,
      `move rejected: ${applied.reason}`,
    );
  }
  state.matches.set(envelope.matchId, applied.state);

  const response: StealResponse = {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action,
    policyProof: { circuitVersion: STEAL_CIRCUIT_VERSION },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey,
    proof: null,
    public_signals: [],
  };

  // publicInputsHash (SPEC.md: keccak256 over 8 fields), computed by
  // the proving module when it provides the function. Never faked.
  const proving = await loadProving();
  if (proving && typeof proving.computeStealPublicInputsHash === "function") {
    try {
      response.policyProof.publicInputsHash =
        proving.computeStealPublicInputsHash({
          strategyCommitmentHash: envelope.strategyCommitment.hash,
          matchId: envelope.matchId,
          turn: envelope.turn,
          selfBalance: envelope.state.selfBalance,
          opponentBalance: envelope.state.opponentBalance,
          action: action.type,
          amount: action.amount ?? 0,
          circuitVersion: STEAL_CIRCUIT_VERSION,
        });
    } catch (err) {
      response.proof_status = `publicInputsHash failed: ${
        err instanceof Error ? err.message : String(err)
      }`;
    }
  } else {
    response.proof_status =
      "computeStealPublicInputsHash unavailable (proving module/function missing)";
  }

  if (!proving) {
    if (!response.proof_status) {
      response.proof_status = "proving module missing";
    }
    return response;
  }

  let proof: GenerateProofResult;
  try {
    // Steal proofs are BLOCKED until the platform publishes vfyPolicy's
    // 8 private input names (SPEC.md / PROVING.md): generateProof("steal")
    // throws a clear error and the server maps it to proof:null below —
    // never a fake proof. The response still carries the verifiable
    // publicInputsHash (computed above). The 8 public-input-hash fields
    // are passed as strings for when the circuit becomes usable.
    const actionCode =
      action.type === "HOLD" ? "0" : action.type === "FORTIFY" ? "1" : "2";
    proof = await proving.generateProof({
      track: "steal",
      circuitInputs: {
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance: envelope.state.selfBalance,
        opponentBalance: envelope.state.opponentBalance,
        action: action.type,
        amount: action.amount ?? 0,
        policyCommitment: state.policyCommitment,
        commitmentHash: envelope.strategyCommitment.hash,
      },
      publicInputs: [
        envelope.strategyCommitment.hash,
        envelope.matchId,
        String(envelope.turn),
        envelope.state.selfBalance,
        envelope.state.opponentBalance,
        actionCode,
        String(action.amount ?? 0),
        "1",
      ],
    });
  } catch (err) {
    response.proof = null;
    response.proof_status = `proving failed: ${
      err instanceof Error ? err.message : String(err)
    }`;
    return response;
  }

  response.proof = proof.proof;
  response.public_signals = proof.publicSignals;
  if (proof.placeholder) {
    response.proof_status =
      "placeholder proof (local circuit, not the platform circuit)";
    return response;
  }

  // Submit the policy proof to Kurier for the on-chain audit pointer.
  if (state.config.kurierApiKey) {
    try {
      const submitted = await submitProof(
        {
          proof: proof.proof,
          publicSignals: proof.publicSignals,
          vkHash: state.config.platformVkHashVfyPolicy,
          circuitVersion: STEAL_CIRCUIT_VERSION,
        },
        {
          apiKey: state.config.kurierApiKey,
          apiUrl: state.config.kurierApiUrl,
          statusPath: state.config.kurierStatusPath,
        },
      );
      if (submitted.proofTx) {
        response.policyProof.proofReference = submitted.proofTx;
      }
      if (!response.proof_status) {
        response.proof_status =
          submitted.status === "Finalized"
            ? "finalized"
            : `kurier status: ${submitted.status}`;
      }
    } catch (err) {
      if (!response.proof_status) {
        response.proof_status = `kurier submission failed: ${
          err instanceof Error ? err.message : String(err)
        }`;
      }
    }
  }
  return response;
}

export function createServer(
  config: AgentConfig = loadConfig(),
): http.Server {
  const state: ServerState = {
    config,
    seenProofTxs: new Set<string>(),
    decisionCache: new Map<string, GatekeeperResponse>(),
    matches: new Map(),
    policyCommitment:
      config.strategyCommitment ?? localPolicyCommitment(),
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";

    // Health / info: no signature required (platform health check).
    if (method === "GET" && url.pathname === "/health") {
      sendJson(
        res,
        200,
        {
          status: "ok",
          agent: config.agentName,
          tracks: [TRACK_GATEKEEPER, "agent-games.steal-vfy.v1"],
        },
        config.hmacSecret,
        config.hmacAlgorithm,
      );
      return;
    }
    if (method === "GET" && url.pathname === "/") {
      sendJson(
        res,
        200,
        {
          agent: config.agentName,
          tracks: [TRACK_GATEKEEPER, "agent-games.steal-vfy.v1"],
          endpoints: ["/agent", "/agent/gatekeeper", "/agent/steal"],
        },
        config.hmacSecret,
        config.hmacAlgorithm,
      );
      return;
    }

    if (method !== "POST") {
      sendJson(
        res,
        404,
        { error: "not found" },
        config.hmacSecret,
        config.hmacAlgorithm,
      );
      return;
    }

    // --- POST: capture raw body, then HMAC-gate BEFORE parsing. ---
    const chunks: Buffer[] = [];
    let bodyBytes = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      bodyBytes += chunk.length;
      if (bodyBytes > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      void (async () => {
        if (tooLarge) {
          sendJson(
            res,
            413,
            { error: "body too large" },
            config.hmacSecret,
            config.hmacAlgorithm,
          );
          return;
        }
        const rawBody = Buffer.concat(chunks);

        // Response-timeout budget: fail closed with 503 if the handler
        // cannot finish inside the budget.
        let finished = false;
        const timer = setTimeout(() => {
          if (finished) return;
          finished = true;
          try {
            sendJson(
              res,
              503,
              { error: "timeout" },
              config.hmacSecret,
              config.hmacAlgorithm,
            );
          } catch {
            /* response already gone */
          }
        }, config.responseTimeoutMs);
        const done = () => {
          finished = true;
          clearTimeout(timer);
        };

        try {
          // HMAC gate (before JSON parse, before any decision).
          const headerValue = config.hmacHeaders
            .map((h) => req.headers[h])
            .find((v) => typeof v === "string");
          if (
            !config.hmacSecret ||
            !verifySignature(
              rawBody,
              headerValue as string | undefined,
              config.hmacSecret,
              config.hmacAlgorithm,
            )
          ) {
            done();
            sendJson(
              res,
              401,
              { error: "invalid or missing signature" },
              config.hmacSecret,
              config.hmacAlgorithm,
            );
            return;
          }

          let body: unknown;
          try {
            body = JSON.parse(rawBody.toString("utf8"));
          } catch {
            done();
            sendJson(
              res,
              400,
              { error: "invalid JSON" },
              config.hmacSecret,
              config.hmacAlgorithm,
            );
            return;
          }

          const path = url.pathname;
          let result: unknown;

          const dispatch = async (): Promise<
            { status: number; body: unknown } | null
          > => {
            const type =
              isRecord(body) && typeof body.type === "string"
                ? body.type
                : "";
            // Preflight: answered after the HMAC check.
            if (type === TRACK_PREFLIGHT) {
              const reply: PreflightResponse = {
                ok: true,
                protocolVersion: "v1",
              };
              return { status: 200, body: reply };
            }
            if (type === TRACK_GATEKEEPER) {
              if (!validGatekeeperEnvelope(body)) {
                return {
                  status: 400,
                  body: { error: "invalid gatekeeper envelope" },
                };
              }
              return {
                status: 200,
                body: await handleGatekeeper(body, state),
              };
            }
            // Steal: dispatch on matchId + turn (the envelope has no
            // `type` field per SPEC.md).
            if (
              isRecord(body) &&
              typeof body.matchId === "string" &&
              typeof body.turn === "number"
            ) {
              if (!validStealEnvelope(body)) {
                return {
                  status: 400,
                  body: { error: "invalid steal envelope" },
                };
              }
              return {
                status: 200,
                body: await handleSteal(body, state),
              };
            }
            return {
              status: 400,
              body: { error: "unknown track" },
            };
          };

          if (path === "/agent/gatekeeper") {
            if (!validGatekeeperEnvelope(body)) {
              done();
              sendJson(
                res,
                400,
                { error: "invalid gatekeeper envelope" },
                config.hmacSecret,
                config.hmacAlgorithm,
              );
              return;
            }
            result = await handleGatekeeper(body, state);
          } else if (path === "/agent/steal") {
            if (!validStealEnvelope(body)) {
              done();
              sendJson(
                res,
                400,
                { error: "invalid steal envelope" },
                config.hmacSecret,
                config.hmacAlgorithm,
              );
              return;
            }
            result = await handleSteal(body, state);
          } else if (path === "/agent/preflight") {
            if (
              !isRecord(body) ||
              body.type !== TRACK_PREFLIGHT
            ) {
              done();
              sendJson(
                res,
                400,
                { error: "invalid preflight envelope" },
                config.hmacSecret,
                config.hmacAlgorithm,
              );
              return;
            }
            const reply: PreflightResponse = {
              ok: true,
              protocolVersion: "v1",
            };
            result = reply;
          } else if (path === "/agent") {
            const dispatched = await dispatch();
            if (!dispatched) {
              done();
              sendJson(
                res,
                404,
                { error: "not found" },
                config.hmacSecret,
                config.hmacAlgorithm,
              );
              return;
            }
            if (dispatched.status !== 200) {
              done();
              sendJson(
                res,
                dispatched.status,
                dispatched.body,
                config.hmacSecret,
                config.hmacAlgorithm,
              );
              return;
            }
            result = dispatched.body;
          } else {
            done();
            sendJson(
              res,
              404,
              { error: "not found" },
              config.hmacSecret,
              config.hmacAlgorithm,
            );
            return;
          }

          if (!finished) {
            done();
            sendJson(res, 200, result, config.hmacSecret, config.hmacAlgorithm);
          }
        } catch (err) {
          if (!finished) {
            done();
            try {
              sendJson(
                res,
                500,
                {
                  error: "internal error",
                  detail: err instanceof Error ? err.message : String(err),
                },
                config.hmacSecret,
                config.hmacAlgorithm,
              );
            } catch {
              /* ignore */
            }
          }
        }
      })();
    });
    req.on("error", () => {
      try {
        sendJson(
          res,
          400,
          { error: "request error" },
          config.hmacSecret,
          config.hmacAlgorithm,
        );
      } catch {
        /* ignore */
      }
    });
  });

  return server;
}

export function main(): void {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.port, config.host, () => {
    console.log(
      `[server] agent "${config.agentName}" listening on ` +
        `${config.host}:${config.port} ` +
        `(hmac secret ${config.hmacSecret ? "set" : "MISSING — dev mode"}, ` +
        `timeout ${config.responseTimeoutMs}ms)`,
    );
  });
}

if (require.main === module) {
  main();
}
