# Architecture (module map)

Agent "muse" — zkVerify Agent Games Season 01.
Stack: Node.js 20+ / TypeScript, zero web framework (plain `node:http`),
`snarkjs` for Groth16 proving, `node:test` for tests.

## Module map (who owns what)

| Path | Owner | Purpose |
| --- | --- | --- |
| `src/server.ts` | core | HTTP server: raw-body capture, HMAC gate, routing, 60s budget, JSON responses |
| `src/types.ts` | core | Shared types: envelopes, decisions, match state, proof payloads |
| `src/hmac.ts` | core | HMAC-SHA256 verify on the raw body (constant-time compare); reject unsigned/tampered |
| `src/gatekeeper.ts` | core | Proof Gatekeeper decision policy (binding checks, NOT just proof validity) |
| `src/steal.ts` | core | Steal the VFY 20-turn state machine, policy moves, idempotency, match/turn validation |
| `src/proving.ts` | proving | Groth16 proof generation via snarkjs; loads circuit artifacts + platform VK (env) |
| `src/config.ts` | core | Env config parsing (PORT, `AGENT_GAMES_HMAC_SECRET`, Kurier key, VK hashes) — never logs secrets |
| `src/kurier.ts` | core | Kurier proof submission (`POST https://api.kurier.xyz/api/v1/submit-proof/${key}`) + Finalized polling |
| `tests/` | core | `node:test` suites: HMAC, gatekeeper, steal machine, proving smoke |
| `circuits/` | proving | Circom sources + `scripts/build-circuits.sh` (circom 2.x + snarkjs, local ceremony) |
| `Dockerfile`, `fly.toml` | proving | Deployment (fly.io) |
| `README.md` | coordinator | Docs + LIMITATIONS |

## Rules that shape every module

1. **Verify HMAC on the raw body FIRST** — before parsing JSON, before any
   decision. Header is `x-agent-games-signature`, HMAC-SHA256 hex over the
   raw body, secret `AGENT_GAMES_HMAC_SECRET` (platform-generated, shown once).
   Unsigned or tampered envelope → 401, no decision, no proof. Every response
   is signed the same way. Preflight (`agent-games.preflight.v1`) is answered
   after the same HMAC check with `{"ok": true, "protocolVersion": "v1"}`.
2. **The decision is scored independently of proof validity.** A perfectly
   valid proof can still authorize the wrong action. Gatekeeper must check the
   binding: public inputs, verification key, task ID, recipient, amount, chain
   — all must match the action being approved. Mismatch → reject.
3. **Never invent the platform's spec.** Header names, envelope field names,
   circuit VKs and the Kurier endpoint are per the official builder field
   guide (SPEC.md). Gatekeeper's 13 input names and public-signal order
   were recovered from the official artifacts and verified by live
   fullProve + local-verify round-trips (PROBE.md). The one remaining
   circuit gap is vfyPolicy's 8 private input names — `generateProof`
   fails loudly with instructions instead of guessing.
4. **60-second response budget** — every handler must finish inside it;
   proving must be fast or fall back to a documented degraded path (never
   silently return an unproven decision as proven).
5. **No secrets in code, logs, or the repo.** Secrets come from env only.
