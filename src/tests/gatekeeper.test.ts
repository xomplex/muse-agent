import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decideGatekeeper } from "../gatekeeper";
import type { GatekeeperInput } from "../types";

function baseInput(overrides: Partial<GatekeeperInput> = {}): GatekeeperInput {
  return {
    registered_vk: "0xabc",
    proof_vk: "0xabc",
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: "0xrecipient",
    condition_recipient: "0xrecipient",
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xtx1",
    ...overrides,
  };
}

const ctx = () => ({
  registeredVk: "0xabc",
  seenProofTxs: new Set<string>(),
});

describe("gatekeeper", () => {
  it("VALID_CONDITION approves when everything binds", () => {
    const r = decideGatekeeper(baseInput(), ctx());
    assert.equal(r.decision, "APPROVE");
    assert.equal(r.reason_code, "VALID_CONDITION");
  });

  it("VK_SUBSTITUTION: proof_vk !== registered_vk", () => {
    const r = decideGatekeeper(baseInput({ proof_vk: "0xother" }), ctx());
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "VK_SUBSTITUTION");
  });

  it("PROOF_REUSED: proof_tx already seen", () => {
    const c = ctx();
    c.seenProofTxs.add("0xtx1");
    const r = decideGatekeeper(baseInput(), c);
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "PROOF_REUSED");
  });

  it("EXPIRED_CONDITION: current_block > expiry_block", () => {
    const r = decideGatekeeper(
      baseInput({ current_block: 19842202 }),
      ctx(),
    );
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "EXPIRED_CONDITION");
  });

  it("EXPIRED_CONDITION: at expiry block itself is still valid", () => {
    const r = decideGatekeeper(
      baseInput({ current_block: 19842201 }),
      ctx(),
    );
    assert.equal(r.decision, "APPROVE");
  });

  it("RECIPIENT_MISMATCH: recipient !== condition_recipient", () => {
    const r = decideGatekeeper(
      baseInput({ recipient: "0xsomeoneelse" }),
      ctx(),
    );
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "RECIPIENT_MISMATCH");
  });

  it("AMOUNT_OVERFLOW: amount > max_transfer", () => {
    const r = decideGatekeeper(baseInput({ amount: "1001" }), ctx());
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "AMOUNT_OVERFLOW");
  });

  it("THRESHOLD_MISMATCH: public_balance < minimum (CORRECTED rule)", () => {
    const r = decideGatekeeper(
      baseInput({ minimum: "2000", public_balance: "1460" }),
      ctx(),
    );
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
  });

  it("amount below minimum does NOT reject when public_balance >= minimum", () => {
    // The threshold check is public_balance >= minimum ONLY (SPEC.md
    // authoritative correction 2026-11-15).
    const r = decideGatekeeper(
      baseInput({ amount: "500", minimum: "1000", public_balance: "1460" }),
      ctx(),
    );
    assert.equal(r.decision, "APPROVE");
    assert.equal(r.reason_code, "VALID_CONDITION");
  });

  it("THRESHOLD_MISMATCH: public_balance exactly at minimum approves", () => {
    const r = decideGatekeeper(
      baseInput({ minimum: "1460", public_balance: "1460" }),
      ctx(),
    );
    assert.equal(r.decision, "APPROVE");
  });

  it("BigInt amounts: values beyond Number.MAX_SAFE_INTEGER compare exactly", () => {
    const big = "9007199254740993"; // MAX_SAFE_INTEGER + 2
    const r = decideGatekeeper(
      baseInput({
        amount: big,
        minimum: big,
        public_balance: big,
        max_transfer: "9007199254740994",
      }),
      ctx(),
    );
    assert.equal(r.decision, "APPROVE");
    const overflow = decideGatekeeper(
      baseInput({
        amount: "9007199254740994",
        minimum: "1",
        public_balance: "9007199254740994",
        max_transfer: big,
      }),
      ctx(),
    );
    assert.equal(overflow.reason_code, "AMOUNT_OVERFLOW");
  });

  it("unparseable amounts fail closed as THRESHOLD_MISMATCH", () => {
    const r = decideGatekeeper(baseInput({ amount: "not-a-number" }), ctx());
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
  });

  it("decideGatekeeper does not mutate the seen set (caller records)", () => {
    const c = ctx();
    decideGatekeeper(baseInput(), c);
    assert.equal(c.seenProofTxs.size, 0);
    // Caller records after computing the decision:
    c.seenProofTxs.add("0xtx1");
    const second = decideGatekeeper(baseInput(), c);
    assert.equal(second.reason_code, "PROOF_REUSED");
  });

  it("priority: VK substitution wins over expiry", () => {
    const r = decideGatekeeper(
      baseInput({ proof_vk: "0xother", current_block: 99999999 }),
      ctx(),
    );
    assert.equal(r.reason_code, "VK_SUBSTITUTION");
  });
});
