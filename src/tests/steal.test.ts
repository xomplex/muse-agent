import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createMatch,
  policyMove,
  validateTurn,
  applyMove,
  isMatchComplete,
  syncFortification,
  ACTION_EXTRACT,
  ACTION_FORTIFY,
  ACTION_HOLD,
  TOTAL_TURNS,
  FORTIFY_COST,
  FORTIFY_BLOCK,
  EXTRACT_MAX,
} from "../steal";
import type { StealEnvelope, StealAction } from "../types";

function envelope(
  state: ReturnType<typeof createMatch>,
  overrides: Partial<StealEnvelope> = {},
): StealEnvelope {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: state.matchId,
    turn: state.turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: {
      selfBalance: String(state.me),
      opponentBalance: String(state.opponent),
      selfFortifiedUntilTurn: state.selfFortifiedUntilTurn,
      opponentFortifiedUntilTurn: state.opponentFortifiedUntilTurn,
    },
    strategyCommitment: { hash: state.policyCommitment },
    resolverVersion: "v1",
    nonce: `nonce-${state.turn}`,
    ...overrides,
  };
}

describe("steal state machine", () => {
  it("20-turn full match completes (turn 20, no more moves)", () => {
    let state = createMatch("m1", "0xcommit");
    for (let turn = 0; turn < TOTAL_TURNS; turn++) {
      assert.equal(state.turn, turn);
      const validation = validateTurn(envelope(state), state);
      assert.equal(validation.ok, true, JSON.stringify(validation));
      const move = policyMove(state);
      // Policy must never extract more than the exposed balance.
      if (move.type === ACTION_EXTRACT) {
        assert.ok(typeof move.amount === "number");
        assert.ok(move.amount >= 1 && move.amount <= EXTRACT_MAX);
        assert.ok(move.amount <= state.opponent);
      }
      if (move.type === ACTION_FORTIFY) {
        assert.equal(move.amount, undefined);
      }
      const applied = applyMove(
        state,
        move,
        `nonce-${turn}`,
        `m1:${turn}:uuid-${turn}`,
      );
      assert.equal(applied.ok, true, JSON.stringify(applied));
      state = applied.state;
    }
    assert.equal(state.turn, 20);
    assert.equal(isMatchComplete(state), true);
    assert.equal(state.history.length, 20);
    // No move after completion.
    const extra = applyMove(
      state,
      { type: ACTION_HOLD },
      "nonce-20",
      "m1:20:uuid-20",
    );
    assert.equal(extra.ok, false);
    const validation = validateTurn(envelope(state), state);
    assert.equal(validation.ok, false);
  });

  it("stale turn rejected", () => {
    const state = createMatch("m1", "0xcommit");
    const env = envelope(state, { nonce: "n0" });
    const first = applyMove(state, { type: ACTION_HOLD }, "n0", "m1:0:u");
    assert.equal(first.ok, true);
    const next = first.state;
    // Replay turn 0 against state expecting turn 1.
    const r = validateTurn(env, next);
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /stale turn/);
  });

  it("reused nonce rejected", () => {
    const state = createMatch("m1", "0xcommit");
    const applied = applyMove(
      state,
      { type: ACTION_HOLD },
      "dup-nonce",
      "m1:0:u",
    );
    assert.equal(applied.ok, true);
    const r = validateTurn(
      envelope(applied.state, { nonce: "dup-nonce" }),
      applied.state,
    );
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /nonce already used/);
    const again = applyMove(
      applied.state,
      { type: ACTION_HOLD },
      "dup-nonce",
      "m1:1:u",
    );
    assert.equal(again.ok, false);
  });

  it("wrong matchId rejected", () => {
    const state = createMatch("m1", "0xcommit");
    const r = validateTurn(envelope(state, { matchId: "m2" }), state);
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /matchId/);
  });

  it("balances mismatch rejected and state does not advance", () => {
    const state = createMatch("m1", "0xcommit");
    const env = envelope(state, {
      state: {
        selfBalance: "999",
        opponentBalance: String(state.opponent),
        selfFortifiedUntilTurn: null,
        opponentFortifiedUntilTurn: null,
      },
    });
    const r = validateTurn(env, state);
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /balances mismatch/);
    assert.equal(state.turn, 0);
  });

  it("strategyCommitment hash mismatch rejected", () => {
    const state = createMatch("m1", "0xcommit");
    const env = envelope(state, {
      strategyCommitment: { hash: "0xdifferent" },
    });
    const r = validateTurn(env, state);
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /strategyCommitment/);
  });

  it("HOLD/FORTIFY with amount rejected by applyMove", () => {
    const state = createMatch("m1", "0xcommit");
    const hold = applyMove(
      state,
      { type: ACTION_HOLD, amount: 0 },
      "k-hold",
      "m1:0:u",
    );
    assert.equal(hold.ok, false);
    const fort = applyMove(
      state,
      { type: ACTION_FORTIFY, amount: 2 },
      "k-fort",
      "m1:0:u",
    );
    assert.equal(fort.ok, false);
  });

  it("FORTIFY cost rule: costs 2, only if me > 2; blocks up to 6 extraction", () => {
    // Behind by 25 → FORTIFY, me 100 - 2 = 98, fortified this turn.
    const behind = {
      ...createMatch("m1", "0xcommit"),
      me: 75,
      opponent: 100,
    };
    assert.equal(policyMove(behind).type, ACTION_FORTIFY);
    const applied = applyMove(
      behind,
      { type: ACTION_FORTIFY },
      "k-f",
      "m1:0:u",
    );
    assert.equal(applied.ok, true);
    assert.equal(applied.state.me, 75 - FORTIFY_COST);
    assert.equal(applied.state.selfFortifiedUntilTurn, 0);

    // Behind but me <= 2 → cannot afford → HOLD.
    const broke = {
      ...createMatch("m1", "0xcommit"),
      me: 2,
      opponent: 100,
    };
    assert.equal(policyMove(broke).type, ACTION_HOLD);
    const cannot = applyMove(
      broke,
      { type: ACTION_FORTIFY },
      "k-broke",
      "m1:0:u",
    );
    assert.equal(cannot.ok, false);
  });

  it("EXTRACT against a fortified opponent is blocked up to 6", () => {
    const fortified = {
      ...createMatch("m1", "0xcommit"),
      opponentFortifiedUntilTurn: 0, // fortified on turn 0
    };
    const applied = applyMove(
      fortified,
      { type: ACTION_EXTRACT, amount: 10 },
      "k-x",
      "m1:0:u",
    );
    assert.equal(applied.ok, true);
    // 10 - 6 blocked = 4 stolen.
    assert.equal(applied.state.me, 100 + (10 - FORTIFY_BLOCK));
    assert.equal(applied.state.opponent, 100 - (10 - FORTIFY_BLOCK));

    // EXTRACT 6 or less against a fortified opponent steals nothing.
    const blocked = applyMove(
      fortified,
      { type: ACTION_EXTRACT, amount: 6 },
      "k-x6",
      "m1:0:u",
    );
    assert.equal(blocked.ok, true);
    assert.equal(blocked.state.me, 100);
    assert.equal(blocked.state.opponent, 100);
  });

  it("EXTRACT policy: bounded fraction, ahead-or-even, not vs fortified", () => {
    const even = createMatch("m1", "0xcommit"); // 100 vs 100
    const move = policyMove(even);
    assert.equal(move.type, ACTION_EXTRACT);
    // min(10, max(1, floor(100*0.10))) = 10
    assert.equal(move.amount, 10);

    // Opponent fortified this turn → no EXTRACT.
    const fortified = syncFortification(
      createMatch("m1", "0xcommit"),
      null,
      0,
    );
    assert.equal(policyMove(fortified).type, ACTION_HOLD);

    // Behind → FORTIFY (not EXTRACT).
    const behind = {
      ...createMatch("m1", "0xcommit"),
      me: 90,
      opponent: 100,
    };
    assert.equal(policyMove(behind).type, ACTION_FORTIFY);
  });

  it("applyMove is immutable-ish: input state is not mutated", () => {
    const state = createMatch("m1", "0xcommit");
    const applied = applyMove(
      state,
      { type: ACTION_HOLD },
      "k-imm",
      "m1:0:u",
    );
    assert.equal(applied.ok, true);
    assert.equal(state.turn, 0);
    assert.equal(state.history.length, 0);
    assert.equal(applied.state.turn, 1);
    assert.equal(applied.state.history.length, 1);
    assert.equal(state.usedNonces.has("k-imm"), false);
  });

  it("EXTRACT amount above 10 rejected", () => {
    const state = createMatch("m1", "0xcommit");
    const r = applyMove(
      state,
      { type: ACTION_EXTRACT, amount: 11 },
      "k-big",
      "m1:0:u",
    );
    assert.equal(r.ok, false);
  });

  it("EXTRACT amount must be a number (not a string)", () => {
    const state = createMatch("m1", "0xcommit");
    const r = applyMove(
      state,
      { type: ACTION_EXTRACT, amount: "5" as unknown as number },
      "k-str",
      "m1:0:u",
    );
    assert.equal(r.ok, false);
  });

  it("syncFortification takes the envelope's fortification fields", () => {
    const state = createMatch("m1", "0xcommit");
    const synced = syncFortification(state, 3, 5);
    assert.equal(synced.selfFortifiedUntilTurn, 3);
    assert.equal(synced.opponentFortifiedUntilTurn, 5);
    assert.equal(state.selfFortifiedUntilTurn, null);
  });
});
