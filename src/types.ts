/**
 * Shared types for the Agent Games agent "muse".
 *
 * Field names follow SPEC.md (authoritative, read 2026-11-15) verbatim.
 * Envelopes allow extra fields — the platform may add fields we have not
 * seen, and they must not break parsing.
 */

// ---------------------------------------------------------------- Preflight

export interface PreflightEnvelope {
  type: "agent-games.preflight.v1";
  agent_id: string;
  issued_at: string;
  nonce: string;
  [key: string]: unknown;
}

export interface PreflightResponse {
  ok: true;
  protocolVersion: "v1";
}

// ---------------------------------------------------------------- Gatekeeper

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  /** Decimal string; compared with BigInt. */
  minimum: string;
  /** Decimal string; compared with BigInt. */
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  /** Decimal string; compared with BigInt. */
  amount: string;
  /** Decimal string; compared with BigInt. */
  max_transfer: string;
  proof_tx: string;
}

export interface GatekeeperEnvelope {
  type: "agent-games.proof-gatekeeper.v1";
  task_id: string;
  mode: string;
  issued_at: string;
  deadline_at: string;
  input: GatekeeperInput;
  [key: string]: unknown;
}

export type GatekeeperDecision = "APPROVE" | "REJECT";

export type GatekeeperReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "THRESHOLD_MISMATCH";

export interface GatekeeperResponse {
  decision: GatekeeperDecision;
  reason_code: GatekeeperReasonCode;
  /** On-chain proof tx if submitted via Kurier, else null. NEVER faked. */
  proof_tx: string | null;
  proof?: unknown;
  public_signals?: string[];
  /** Explains why proof/proof_tx is absent when it is (degraded path). */
  proof_status?: string;
}

// ---------------------------------------------------------------- Steal the VFY

export type StealActionType = "EXTRACT" | "FORTIFY" | "HOLD";

/**
 * action.amount is a NUMBER in the response (SPEC.md example:
 * {"type":"EXTRACT","amount":5}) and must be OMITTED entirely for
 * HOLD/FORTIFY — the platform schema rejects it even as 0.
 */
export interface StealAction {
  type: StealActionType;
  amount?: number;
}

export interface StealGameState {
  /** Decimal strings in the envelope. */
  selfBalance: string;
  opponentBalance: string;
  /** Turn number through which fortification is active, or null. */
  selfFortifiedUntilTurn: number | null;
  opponentFortifiedUntilTurn: number | null;
}

export interface StealEnvelope {
  protocolVersion: "v1";
  eventId: "steal-the-vfy";
  mode: string;
  matchId: string;
  turn: number;
  issuedAt: string;
  deadlineAt: string;
  state: StealGameState;
  strategyCommitment: { hash: string };
  resolverVersion: string;
  nonce: string;
  [key: string]: unknown;
}

export interface StealPolicyProof {
  /** SPEC.md: "v1". */
  circuitVersion: "v1";
  /** On-chain audit pointer (Kurier proof tx), when available. */
  proofReference?: string;
  /** keccak256 public-inputs hash, when computable. Never faked. */
  publicInputsHash?: string;
}

export interface StealResponse {
  matchId: string;
  turn: number;
  action: StealAction;
  policyProof: StealPolicyProof;
  agentTimestamp: string;
  /** Never repeats across turns: `${matchId}:${turn}:${uuid}`. */
  idempotencyKey: string;
  /** Groth16 proof, when proving succeeded (extra field, not in the
   *  SPEC.md response example — included for auditability). */
  proof?: unknown;
  public_signals?: string[];
  proof_status?: string;
}

/** Request shape for computeStealPublicInputsHash (from ./proving). */
export interface StealPublicInputsHashRequest {
  strategyCommitmentHash: string;
  matchId: string;
  turn: number;
  selfBalance: string | number;
  opponentBalance: string | number;
  action: StealActionType;
  amount: number;
  circuitVersion?: string;
}

// ------------------------------------------------------------ Proving / Kurier

export type ProvingTrack = "gatekeeper" | "steal";

export interface GenerateProofRequest {
  track: ProvingTrack;
  circuitInputs: Record<string, unknown>;
  publicInputs: string[];
}

export interface GenerateProofResult {
  proof: unknown;
  publicSignals: string[];
  circuit: string;
  circuitVersion: string;
  /** True when the proof is a local placeholder, not a platform proof. */
  placeholder: boolean;
}

export interface SubmitProofRequest {
  proof: unknown;
  publicSignals: string[];
  vkHash: string;
  circuitVersion: string;
}

export interface SubmitProofResult {
  jobId: string;
  proofTx: string | null;
  status: string;
}

// ---------------------------------------------------------------- Health / misc

export interface HealthResponse {
  status: "ok";
  agent: string;
  tracks: string[];
}
