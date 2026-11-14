import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  verifySignature,
  signResponse,
  computeHmac,
  normalizeSignatureHeader,
  SIGNATURE_HEADER,
  HMAC_ALGORITHM,
} from "../hmac";

const SECRET = "test-only-secret-never-real";
const WRONG_SECRET = "a-different-test-secret";
const BODY = Buffer.from(
  JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", task_id: "gk_1" }),
);

describe("hmac", () => {
  it("header is the exact spec header, algorithm sha256", () => {
    assert.equal(SIGNATURE_HEADER, "x-agent-games-signature");
    assert.equal(HMAC_ALGORITHM, "sha256");
  });

  it("valid signature passes", () => {
    const sig = signResponse(BODY, SECRET);
    assert.equal(verifySignature(BODY, sig, SECRET), true);
  });

  it("tampered body fails", () => {
    const sig = signResponse(BODY, SECRET);
    const tampered = Buffer.from(
      JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", task_id: "gk_2" }),
    );
    assert.equal(verifySignature(tampered, sig, SECRET), false);
  });

  it("missing header fails", () => {
    assert.equal(verifySignature(BODY, undefined, SECRET), false);
    assert.equal(verifySignature(BODY, "", SECRET), false);
    assert.equal(verifySignature(BODY, null, SECRET), false);
  });

  it('"sha256=" prefix accepted', () => {
    const sig = signResponse(BODY, SECRET);
    assert.equal(verifySignature(BODY, `sha256=${sig}`, SECRET), true);
  });

  it("wrong secret fails", () => {
    const sig = signResponse(BODY, SECRET);
    assert.equal(verifySignature(BODY, sig, WRONG_SECRET), false);
  });

  it("one-byte tamper in the signature fails (constant-time compare)", () => {
    const sig = signResponse(BODY, SECRET);
    const last = sig[sig.length - 1];
    const flipped = last === "0" ? "1" : "0";
    const tamperedSig = sig.slice(0, -1) + flipped;
    assert.notEqual(tamperedSig, sig);
    assert.equal(verifySignature(BODY, tamperedSig, SECRET), false);
  });

  it("non-hex header fails", () => {
    assert.equal(verifySignature(BODY, "not-hex!!", SECRET), false);
  });

  it("computeHmac matches the standard sha256 digest", () => {
    const crypto = require("node:crypto");
    const expected = crypto
      .createHmac("sha256", SECRET)
      .update(BODY)
      .digest("hex");
    assert.equal(computeHmac(BODY, SECRET), expected);
  });

  it("normalizeSignatureHeader returns null for garbage", () => {
    assert.equal(normalizeSignatureHeader(""), null);
    assert.equal(normalizeSignatureHeader("zzz"), null);
    assert.equal(normalizeSignatureHeader("abc"), null); // odd length
  });
});
