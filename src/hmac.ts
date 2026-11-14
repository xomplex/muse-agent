/**
 * HMAC signing / verification for Agent Games envelopes.
 *
 * SPEC.md (authoritative): "Every inbound request carries header
 * `x-agent-games-signature` = HMAC-SHA256 (hex) over the RAW body.
 * Verify it BEFORE parsing." And: "Every response must be signed the
 * same way (same header, over the raw response body)."
 * Secret: `AGENT_GAMES_HMAC_SECRET` (platform-generated, shown once).
 *
 * NEVER log the secret or the computed digest in a way that leaks it;
 * this module logs nothing at all.
 */
import crypto from "node:crypto";

/** Header carrying the signature, inbound and outbound (exact per SPEC.md). */
export const SIGNATURE_HEADER = "x-agent-games-signature";
/** Backwards-compatible alias. */
export const RESPONSE_SIGNATURE_HEADER = SIGNATURE_HEADER;

/** HMAC algorithm (exact per SPEC.md). */
export const HMAC_ALGORITHM = "sha256";

/**
 * Normalize an incoming signature header value to bare hex, accepting
 * both a bare hex digest and the "sha256=<hex>" (or "<algo>=<hex>") form.
 * Returns null when the value cannot be interpreted as hex.
 */
export function normalizeSignatureHeader(
  headerValue: string | undefined | null,
): string | null {
  if (!headerValue) return null;
  const trimmed = headerValue.trim();
  if (trimmed.length === 0) return null;
  const eq = trimmed.indexOf("=");
  const hex = eq >= 0 ? trimmed.slice(eq + 1).trim() : trimmed;
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return null;
  return hex.toLowerCase();
}

/**
 * Compute the HMAC hex digest of a raw body for a given secret/algorithm.
 * Throws on an unsupported algorithm — the caller must fail closed.
 */
export function computeHmac(
  rawBody: Buffer,
  secret: string,
  algorithm = HMAC_ALGORITHM,
): string {
  return crypto
    .createHmac(algorithm, secret)
    .update(rawBody)
    .digest("hex");
}

/**
 * Verify an incoming signature against the raw request body.
 * Accepts a bare hex digest or an "<algo>=<hex>" prefixed value.
 * Constant-time comparison via crypto.timingSafeEqual — a one-byte
 * difference must fail, and the comparison time must not leak the
 * position of the mismatch.
 */
export function verifySignature(
  rawBody: Buffer,
  headerValue: string | undefined | null,
  secret: string,
  algorithm = HMAC_ALGORITHM,
): boolean {
  const presented = normalizeSignatureHeader(headerValue);
  if (!presented) return false;
  let expected: string;
  try {
    expected = computeHmac(rawBody, secret, algorithm);
  } catch {
    // Unsupported algorithm: fail closed, never accept.
    return false;
  }
  const a = Buffer.from(presented, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Sign an outgoing response body. Returns the bare hex digest; the
 * caller sets it as the `x-agent-games-signature` header.
 */
export function signResponse(
  rawBody: Buffer,
  secret: string,
  algorithm = HMAC_ALGORITHM,
): string {
  return computeHmac(rawBody, secret, algorithm);
}
