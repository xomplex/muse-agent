/**
 * Proof Gatekeeper decision policy.
 *
 * The decision is scored INDEPENDENTLY of proof validity (ARCHITECTURE.md
 * rule 2): a perfectly valid proof can still authorize the wrong action.
 * This module checks the BINDING between the proof's public inputs and the
 * action being approved — verification key, task, recipient, amount, chain
 * state — and rejects on any mismatch.
 *
 * Decision rule (EXACT, SPEC.md authoritative): APPROVE ONLY when ALL hold:
 *   proof_vk == registered_vk
 *   public_balance >= minimum
 *   current_block <= expiry_block
 *   recipient == condition_recipient
 *   amount <= max_transfer
 *   the incoming proof is not reused
 * Otherwise REJECT with the matching reason code, checked in this order:
 *   1. VK_SUBSTITUTION     proof_vk !== registered_vk
 *   2. PROOF_REUSED        proof_tx already seen
 *   3. EXPIRED_CONDITION   current_block > expiry_block
 *   4. RECIPIENT_MISMATCH  recipient !== condition_recipient
 *   5. AMOUNT_OVERFLOW     amount > max_transfer
 *   6. THRESHOLD_MISMATCH  public_balance < minimum
 * NOTE: amount is NOT compared against minimum — the threshold check is
 * `public_balance >= minimum` ONLY (corrected 2026-11-15; the old
 * "amount < minimum" reading was wrong).
 *
 * Fail closed: any unparseable numeric field (amount/minimum/etc. not a
 * decimal integer) is rejected as THRESHOLD_MISMATCH — the condition cannot
 * be shown to hold, so it is not approved.
 *
 * Amounts are decimal strings and ALL comparisons use BigInt, so values
 * beyond Number.MAX_SAFE_INTEGER compare exactly.
 *
 * proof_tx seen-set: the caller owns the Set<string> and decides when to
 * record. `decideGatekeeper` NEVER mutates the set itself; see the doc on
 * `decideGatekeeper` for the recommended recording point. This keeps the
 * pure function testable and lets the caller record only after a decision
 * has actually been computed (and, if desired, only after a proof was
 * produced/submitted).
 */
import type {
  GatekeeperInput,
  GatekeeperReasonCode,
} from "./types";

export const REASON_VALID_CONDITION: GatekeeperReasonCode =
  "VALID_CONDITION";
export const REASON_VK_SUBSTITUTION: GatekeeperReasonCode =
  "VK_SUBSTITUTION";
export const REASON_PROOF_REUSED: GatekeeperReasonCode = "PROOF_REUSED";
export const REASON_EXPIRED_CONDITION: GatekeeperReasonCode =
  "EXPIRED_CONDITION";
export const REASON_RECIPIENT_MISMATCH: GatekeeperReasonCode =
  "RECIPIENT_MISMATCH";
export const REASON_AMOUNT_OVERFLOW: GatekeeperReasonCode =
  "AMOUNT_OVERFLOW";
export const REASON_THRESHOLD_MISMATCH: GatekeeperReasonCode =
  "THRESHOLD_MISMATCH";

export interface GatekeeperDecisionResult {
  decision: "APPROVE" | "REJECT";
  reason_code: GatekeeperReasonCode;
}

export interface GatekeeperContext {
  /** The platform-registered verification key for this task/agent. */
  registeredVk: string;
  /** Caller-owned store of proof_tx values already decided on. */
  seenProofTxs: Set<string>;
  /**
   * Optional override for the current chain block. Defaults to
   * `input.current_block` from the envelope when omitted.
   */
  nowBlock?: number;
}

function parseAmount(value: string): bigint | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^-?\d+$/.test(trimmed)) return null;
  try {
    return BigInt(trimmed);
  } catch {
    return null;
  }
}

/**
 * Pure decision function. Does not mutate `ctx.seenProofTxs`.
 *
 * Recording rule (caller responsibility): after computing the decision,
 * add `input.proof_tx` to the seen set — for BOTH APPROVE and REJECT
 * outcomes — so the same proof_tx can never be decided on twice. The
 * server does this immediately after `decideGatekeeper` returns (and its
 * task_id cache makes a platform resend return the same decision without
 * re-deciding).
 */
export function decideGatekeeper(
  input: GatekeeperInput,
  ctx: GatekeeperContext,
): GatekeeperDecisionResult {
  const reject = (
    reason_code: GatekeeperReasonCode,
  ): GatekeeperDecisionResult => ({ decision: "REJECT", reason_code });

  // (1) VK substitution
  if (input.proof_vk !== ctx.registeredVk) {
    return reject(REASON_VK_SUBSTITUTION);
  }

  // (2) Proof reuse
  if (input.proof_tx && ctx.seenProofTxs.has(input.proof_tx)) {
    return reject(REASON_PROOF_REUSED);
  }

  // (3) Expired condition
  const currentBlock = ctx.nowBlock ?? input.current_block;
  if (
    typeof currentBlock !== "number" ||
    typeof input.expiry_block !== "number" ||
    currentBlock > input.expiry_block
  ) {
    return reject(REASON_EXPIRED_CONDITION);
  }

  // (4) Recipient mismatch
  if (input.recipient !== input.condition_recipient) {
    return reject(REASON_RECIPIENT_MISMATCH);
  }

  // Numeric fields: unparseable → fail closed.
  const amount = parseAmount(input.amount);
  const maxTransfer = parseAmount(input.max_transfer);
  const minimum = parseAmount(input.minimum);
  const publicBalance = parseAmount(input.public_balance);
  if (
    amount === null ||
    maxTransfer === null ||
    minimum === null ||
    publicBalance === null
  ) {
    return reject(REASON_THRESHOLD_MISMATCH);
  }

  // (5) Amount overflow
  if (amount > maxTransfer) {
    return reject(REASON_AMOUNT_OVERFLOW);
  }

  // (6) Threshold mismatch: public_balance >= minimum ONLY.
  if (publicBalance < minimum) {
    return reject(REASON_THRESHOLD_MISMATCH);
  }

  return { decision: "APPROVE", reason_code: REASON_VALID_CONDITION };
}
