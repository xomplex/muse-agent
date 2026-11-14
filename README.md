# muse — zkVerify Agent Games agent (Season 01)

Agent **"muse"** for the [zkVerify Agent Games](https://agentgames.zkverify.io/)
Season 01 (21 Oct – 21 Nov 2026). Two arena tracks:

- **Proof Gatekeeper** — approve/reject proof-backed payment requests, with
  a real Groth16 proof (platform's official circuit) attached to every
  decision.
- **Steal the VFY** — 20-turn head-to-head strategy matches, 100 VFY each,
  with a committed policy and a verifiable `publicInputsHash` per move.

> **Status: NOT registered, NOT deployed, NOT pushed.** This repo is a
> local build, complete and tested, waiting for the user to create the
> public GitHub repo (`muse-agent` on the personal account `xomplex`),
> deploy it, and register it on the Agent Games dashboard. Nothing here
> talks to the platform yet.

## Quick start

```sh
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (see below)
npm start              # listens on http://0.0.0.0:3000
```

```sh
npm test               # 81 tests, 0 failures (see "Tests")
```

## How it works

```
platform POST /agent  (header x-agent-games-signature, HMAC-SHA256 over raw body)
  -> HMAC verified BEFORE parsing (401 otherwise, no decision)
  -> preflight: {"ok": true, "protocolVersion": "v1"}
  -> gatekeeper: decide + prove (Groth16, platform circuit)
  -> steal: policy move + publicInputsHash (+ proof when the circuit allows)
  -> every response signed the same way (x-agent-games-signature)
```

- **Gatekeeper decision rule** (SPEC.md): APPROVE only when `proof_vk ==
  registered_vk` AND `public_balance >= minimum` AND `current_block <=
  expiry_block` AND `recipient == condition_recipient` AND `amount <=
  max_transfer` AND the proof is not reused. Otherwise REJECT with the
  matching reason code (`VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`,
  `PROOF_REUSED`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`,
  `AMOUNT_OVERFLOW`). A valid proof of a wrong action is still rejected —
  the decision checks the binding, not just proof validity.
- **Steal policy** (`src/steal.ts`): EXTRACT `min(10, floor(opponent ×
  0.10))` when ahead-or-even and the opponent is unfortified; FORTIFY
  (costs 2 VFY, blocks up to 6 incoming extraction that turn) when behind
  and balance allows; HOLD otherwise. `action.amount` is omitted for
  HOLD/FORTIFY. `idempotencyKey` is unique per turn
  (`matchId:turn:uuid`). The strategy fingerprint is the SHA-256 of the
  policy description in `src/server.ts` (`localPolicyCommitment`) —
  replace `STRATEGY_COMMITMENT` with the registered commitment hash once
  registered; it is frozen once play starts.
- **Proving** (`src/proving.ts`, details in `PROVING.md`): snarkjs +
  the platform's official published circuits (`circuits/artifacts/`).
  Gatekeeper proofs are REAL and verified live (fullProve + local
  `groth16.verify` round-trips in the test suite, ~0.7–2 s per proof,
  inside the 60 s budget). The server enforces a 55 s response budget
  and fails closed with 503 on timeout. `task_id` is the Gatekeeper
  idempotency key — a platform resend returns the cached decision.
- **Proof submission** (`src/kurier.ts`): proofs are submitted to
  zkVerify via Kurier (recommended), `POST
  https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}`, polled
  Submitted → IncludedInBlock → Finalized. Without a Kurier key the
  server still returns the proof in the response and `proof_tx` stays
  `null`. A proof is never fabricated: if proving fails, the response
  carries `proof: null` and `proof_status` explains why.

## Deploy (fly.io)

```sh
fly deploy
fly secrets set AGENT_GAMES_HMAC_SECRET=<from the dashboard> KURIER_API_KEY=<from zkVerify>
fly open   # note the public https://muse-agent.fly.dev URL
```

`fly.toml` targets region `sin` (Singapore) with one machine always
running (`auto_stop_machines = "off"`). The Dockerfile is two-stage
(Node 22 slim, non-root, health check on `GET /health`).

## Register

1. Create the public repo on the **personal** GitHub account (`xomplex`,
   already connected) — suggested name `muse-agent` — and push this repo.
2. On the Agent Games dashboard, register the agent:
   - **Repository URL:** `https://github.com/xomplex/muse-agent`
   - **Agent Endpoint:** `https://muse-agent.fly.dev/agent`
   - Agent name `muse`, both arena tracks.
3. The dashboard shows the HMAC secret **once** at registration — copy it
   into `.env` / `fly secrets set` immediately (it is never shown again;
   it can be rotated from agent settings).
4. Get a Kurier API key from zkVerify and set `KURIER_API_KEY` the same
   way (the Gatekeeper agent still works without it, but `proof_tx` stays
   `null`).
5. Pass the signed preflight (automatic once the endpoint is live) and
   run at least one practice task/turn (practice mode: 10 dispatches per
   active agent per hour, no leaderboard effect).
6. Prize eligibility requires the connected GitHub account + a connected
   wallet address.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `PORT` | no | `3000` | |
| `HOST` | no | `0.0.0.0` | |
| `AGENT_NAME` | no | `muse` | |
| `AGENT_GAMES_HMAC_SECRET` | **yes** | — | 32-byte random from the dashboard, shown once. Without it the server starts in dev mode and rejects every signed request. Never commit. |
| `KURIER_API_URL` | no | `https://api.kurier.xyz` | |
| `KURIER_API_KEY` | no | — | From zkVerify. Without it, proofs are returned but never submitted (`proof_tx: null`). |
| `STRATEGY_COMMITMENT` | no | local SHA-256 of the policy | The registered strategy-commitment hash for Steal the VFY (frozen once play starts). |
| `PLATFORM_VK_HASH_GATEKEEPER` | no | `0x6b79…77b0` | Public platform constant (circuit-info). |
| `PLATFORM_VK_HASH_VFYPOLICY` | no | `0x6c56…e047` | Public platform constant (circuit-info). |
| `CIRCUIT_DIR` | no | `./circuits/artifacts` | |
| `KURIER_STATUS_PATH` | no | `/api/v1/proof-status` | See LIMITATIONS. |
| `RESPONSE_TIMEOUT_MS` | no | `55000` | Must stay < 60000 (platform hard deadline). |

Secrets come from env / `fly secrets set` only. No secrets, keys, or seed
phrases are committed in this repo — ever.

## Tests

```sh
npm test   # build + node --test dist/tests/*.test.js
```

81 tests, 0 failures, ~8 s (10 suites): HMAC verification
(valid/tampered/missing/wrong-secret), Gatekeeper decisions (all 7 reason
codes, incl. valid proof + wrong recipient = REJECT and valid proof +
right binding = APPROVE), Steal state machine (20 turns, fortification
blocking, EXTRACT cap, HOLD/FORTIFY-with-amount rejection), server
(preflight, signed/unsigned, task_id resend, both deadline rules), real
Gatekeeper proving round-trips (APPROVE + REJECT + wrong-decision assert
+ tampered-signals fail), and `computeStealPublicInputsHash` against
independent keccak reference vectors. Test files live in `src/tests/`.

## Schedule reality (as of 15 Nov 2026)

- **Steal the VFY is very likely CLOSED to new entries** — it runs
  13–17 Nov, Swiss 5 rounds → Top 16 knockout; as of 15 Nov ~00:01 WIB
  it is already in round R2 with 9 agents paired, and entries lock once
  the tournament is paired. The track is still fully implemented here.
- **Gatekeeper is still joinable** — 8 daily scored rounds 13–21 Nov,
  17:30–03:30 WIB, 8 tasks/agent/round, cumulative score; entries lock
  while a round is open. Round 02 is live until 03:30 WIB, so
  registration can only complete between rounds and the agent would join
  from Round 03.
- Season closes 21 Nov; judging 22–30 Nov.

## Prize reality

400,000 VFY total (100,000/track; 50,000/30,000/20,000 top 3). VFY
~$0.0045 (all-time low) → 1st place ≈ $225, 3rd ≈ $90, total pool
≈ $1,800. Small money — this build is deliberately lean.

## LIMITATIONS (read before registering)

- **PROOF_REUSED returns no proof — by design.** The Gatekeeper circuit
  asserts `decision == its evaluated condition`, and for a reused proof
  all five on-circuit conditions hold, so no witness exists for a REJECT
  decision. The server returns the REJECT with reason code `PROOF_REUSED`
  and `proof: null` (with a clear `proof_status`) rather than a proof of
  the wrong decision. All other reject codes still carry a real proof.
- **Steal the VFY proofs are BLOCKED.** The vfyPolicy circuit's input
  names are only 9/17 recovered (`commitment, matchId, turnNumber,
  selfBalance, opponentBalance, action, amount, circuitVersion, salt`);
  the remaining 8 are private policy inputs whose names are not published
  anywhere and cannot be guessed. `generateProof("steal")` throws a
  clear error and the server returns `proof: null` for Steal turns. The
  Steal response still carries the published `publicInputsHash`
  (keccak256 over the 8 SPEC fields — implemented exactly, tested against
  independent reference vectors), which the platform can check without a
  proof. If the platform publishes the missing names, re-run
  `node scripts/probe-input-names.mjs`, extend the translator in
  `src/proving.ts`, and re-run `npm test` (see PROVING.md).
- **Gatekeeper `taskId` encoding is an assumption.** Alphanumeric ids
  (e.g. `gk_24_9d1`) are encoded as the big-endian integer of their
  UTF-8 bytes. Proofs verify cryptographically either way, but the
  platform's reading of public signal 12 depends on this encoding
  matching theirs.
- **Kurier job-status path is an assumption.** The guide publishes only
  the submit endpoint, not the status path; polling uses
  `${KURIER_API_URL}${KURIER_STATUS_PATH}/${jobId}` (default
  `/api/v1/proof-status`, env-overridable). If the path is wrong, proofs
  still return in the response and `proof_tx` stays `null` with a
  `kurier status` note — the response never fails because of it.
- **Fortification "until turn" is inclusive** (`syncFortification` in
  `src/steal.ts`): a fortification active "until turn N" blocks the
  first 6 of an incoming EXTRACT during turn N. If the platform means
  exclusive, one line changes.
- **Dockerfile / fly.toml are NOT build-verified** — no Docker or fly CLI
  on the build VM. Verify with `docker build .` or a `fly deploy` dry
  run before relying on them.
- **The platform's exact `task_id`/`idempotencyKey` resend behaviour,
  whether a registered agent can be edited later, and the "3 agent
  slots" rule are not stated anywhere readable** — see SPEC.md.
- First `require("snarkjs")` in a fresh process is slow (tens of
  seconds); the server imports it once at startup, warm proofs are ~1 s.

## Repo layout

```
src/
  server.ts     HTTP server (raw-body HMAC gate, routing, 55 s budget)
  hmac.ts       HMAC-SHA256 verify/sign (x-agent-games-signature)
  gatekeeper.ts decision rule (7 reason codes)
  steal.ts      20-turn match state machine + policy
  proving.ts    snarkjs Groth16 proving + computeStealPublicInputsHash
  kurier.ts     Kurier submission + Finalized polling
  config.ts     env config (never logs secrets)
  types.ts      envelope/response types (verbatim from SPEC.md)
  tests/        81 tests
circuits/
  artifacts/    official platform .wasm/.zkey/.vkey.json + CHECKSUMS.txt,
                INSPECT.md (VK public-input counts), PROBE.md (recovered
                input names)
  README.md     circuit notes
scripts/
  download-artifacts.sh  idempotent re-download + checksum verify
  inspect-circuits.mjs   re-export VKs, regenerate INSPECT.md
  probe-input-names.mjs  FNV-1a oracle probe, regenerate PROBE.md
SPEC.md         the authoritative spec (from the official builder field guide)
ARCHITECTURE.md design rules (fail closed, never fake a proof, never invent spec)
PROVING.md      proving flow, costs, verified facts, TBD list
```

## Never

- Never fake a proof. Never guess circuit input names. Never commit
  secrets. Never claim this agent is registered or deployed — it is
  neither, until the user does the steps under "Register".
