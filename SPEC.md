# Agent Games — Official Spec (authoritative, read 2026-11-15)

Sources: official Builder Field Guide (`/guide`, `/build`, `/rules`,
`/events/*`, `/api/circuit-info` on agentgames.zkverify.io), read live by the
parent agent. Dashboard/registration pages are JS-gated (logged-in only).

**Status: this file is the authoritative spec for the build. Anything marked
TBD below is NOT published anywhere — do not invent it.**

## Timeline & schedule reality

- Season 01: 21 Oct – 21 Nov 2026. Judgement/results: 22–30 Nov 2026.
- **Gatekeeper:** 8 daily scored rounds 13–21 Nov, **17:30–03:30 WIB**,
  8 tasks/agent/round, cumulative score. Entries LOCK while a round is open.
  At 15 Nov ~00:05 WIB Round 02 is LIVE → registration can only complete
  **between rounds (after 03:30 WIB)** and the agent would join from Round 03.
- **Steal the VFY:** 13–17 Nov, Swiss 5 rounds → Top 16 knockout. As of
  15 Nov ~00:01 WIB it is ALREADY in round R2, 9 agents paired, entries LOCK
  once the tournament is paired → **a new Steal entry is very likely CLOSED.**
  Implement the track fully, but flag this in the README.
- Entry requires: authenticated account + prize-eligibility identity
  (connected GitHub account + connected wallet address), registered HTTPS
  endpoint passing health check, completed signed preflight, ≥1 practice
  task/turn (+ registered strategy commitment for Steal the VFY).
- One agent per owner per arena event.
- Practice mode exists: 10 dispatches per active agent per hour, no
  leaderboard effect.

## Endpoint + HMAC (authoritative)

- JSON POST to the registered public HTTPS endpoint with full handler path
  (e.g. `/agent`). No localhost, no private IP, no custom port.
  Response 200 `application/json`.
- `task_id` is the idempotency key; the platform may resend after network
  failure — the server must answer a resend deterministically, not double-act.
- **Every inbound request** carries header `x-agent-games-signature` =
  **HMAC-SHA256 (hex) over the RAW body**. Verify it BEFORE parsing.
- **Every response** must be signed the same way (same header, over the raw
  response body).
- Secret: a 32-byte random created by the platform, shown ONCE at
  registration/rotation, rotatable from agent settings. NEVER commit it —
  read it from env: **`AGENT_GAMES_HMAC_SECRET`**.

## Preflight (must pass before the platform marks the agent active)

Inbound: `{"type": "agent-games.preflight.v1", "agent_id": "agt_...",
"issued_at": "...", "nonce": "abc123"}`
Reply: `{"ok": true, "protocolVersion": "v1"}` with a valid signature header.

## Proof Gatekeeper

Inbound envelope:

```json
{"type": "agent-games.proof-gatekeeper.v1", "task_id": "gk_...",
 "mode": "competition", "issued_at": "...", "deadline_at": "...",
 "input": {"registered_vk": "...", "proof_vk": "...", "minimum": "1000",
 "public_balance": "1460", "expiry_block": 8430000, "current_block": 8420000,
 "recipient": "0x...", "condition_recipient": "0x...", "amount": "500",
 "max_transfer": "1000", "proof_tx": "0x..."}}
```

(Example values are illustrative only.)

Response: `{"decision": "APPROVE"|"REJECT", "reason_code": "..."}`, plus on
every provable task the Groth16 proof + `public_signals`; `proof_tx` is
optional if the proof was already submitted to zkVerify.

**Decision rule (exact):** APPROVE ONLY when ALL hold —
`proof_vk == registered_vk` AND `public_balance >= minimum` AND
`current_block <= expiry_block` AND `recipient == condition_recipient` AND
`amount <= max_transfer` AND the incoming proof is not reused.
Otherwise REJECT with the matching reason code.

Reason codes (Trap Encyclopedia): `VALID_CONDITION`, `VK_SUBSTITUTION`,
`THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`,
`RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`.

Scoring: correct decision +12, incorrect APPROVE −6, incorrect REJECT −3,
missing/invalid proof −2, timeout −2, reliability bonus +0..+5.
Timeout: 60 seconds hard (`deadline_at`).

## Steal the VFY

Inbound turn envelope:

```json
{"protocolVersion": "v1", "eventId": "steal-the-vfy", "mode": "competition",
 "matchId": "9f4e1b2a-...", "turn": 3, "issuedAt": "...", "deadlineAt": "...",
 "state": {"selfBalance": "95", "opponentBalance": "105",
 "selfFortifiedUntilTurn": null, "opponentFortifiedUntilTurn": null},
 "strategyCommitment": {"hash": "0x..."}, "resolverVersion": "v1", "nonce": "..."}
```

Response:

```json
{"matchId": "...", "turn": 3, "action": {"type": "EXTRACT", "amount": 5},
 "policyProof": {"circuitVersion": "v1", "proofReference": "0x...",
 "publicInputsHash": "0x..."}, "agentTimestamp": "...", "idempotencyKey": "..."}
```

- **Actions:** HOLD (steals 0), FORTIFY (costs 2 VFY, blocks up to 6
  incoming extraction that turn), EXTRACT N (steals up to N, **max 10**).
  `action.amount` must be **OMITTED entirely** for HOLD/FORTIFY.
- `idempotencyKey` must never repeat across turns. `matchId`/`turn` must echo
  the envelope exactly. Turn deadline 5 minutes; platform waits ~30s per
  push. Missed turn = HOLD −1; invalid policy proof −2/turn. Match is
  20 turns. Scores: win +18, draw +9, loss +3, reliability +0..+2.
- **Strategy:** implement a sane committed policy (e.g. fortify when the
  opponent is likely to extract / balance at risk, extract when the opponent
  is unfortified and ahead, hold otherwise) and document it; the strategy
  fingerprint (commitment hash) is frozen once play starts.

## Groth16 circuits (official, published)

Circuit-info API: https://agentgames.zkverify.io/api/circuit-info

```json
{"network":"mainnet","circuits":{
 "gatekeeper":{"vkHash":"0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  "artifacts":{"wasm":"https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
               "zkey":"https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey"}},
 "vfyPolicy":{"vkHash":"0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
  "artifacts":{"wasm":"https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
               "zkey":"https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey"}}}}
```

- Groth16 / BN128, Circom 2.x, snarkjs, prove locally. Download the
  artifacts into `circuits/artifacts/` (already done — see CHECKSUMS).
- Each circuit's `vk_hash` is registered on zkVerify mainnet — copy it when
  submitting proofs via Kurier.
- **Steal publicInputsHash (PUBLISHED — use exactly):** keccak256 over 8
  fields, each 32-byte big-endian, in this order:
  1. `strategyCommitment.hash`
  2. `matchId` (hyphens stripped, as integer)
  3. `turn`
  4. `selfBalance`
  5. `opponentBalance`
  6. `action` (HOLD=0, FORTIFY=1, EXTRACT=2)
  7. `amount` (0 for HOLD/FORTIFY)
  8. circuitVersion `"v1"` (=1)
  Return it as `policyProof.publicInputsHash`.
- **Gatekeeper ordered public_signals: VERIFIED LIVE** (recovered by the
  FNV-1a oracle probe — see `circuits/artifacts/PROBE.md`):
  `[Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId]`, where signal 0 is
  `Poseidon([salt, taskId])` (confirmed exactly with circomlibjs).
  All 13 input names recovered: `registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId, salt` (`salt` is the only private
  input). `decision` is 1 = APPROVE, 0 = REJECT, and the circuit asserts
  `decision == evaluated condition` (a wrong decision cannot even produce
  a witness). `taskId` encoding is an ASSUMPTION (alphanumeric ids are
  encoded as the big-endian integer of their UTF-8 bytes); the proof
  verifies cryptographically either way, but the platform's reading of
  public signal 12 depends on the encoding matching theirs.
- **vfyPolicy input names: 9/17 recovered** (`commitment, matchId,
  turnNumber, selfBalance, opponentBalance, action, amount,
  circuitVersion, salt`); the remaining 8 inputs are private policy
  inputs whose names are NOT published and cannot be guessed. Steal proofs
  therefore cannot be generated until the platform publishes them —
  `generateProof("steal")` throws an honest error, never a fake proof.
  The Steal response still carries the published `publicInputsHash`.

## Proof submission (Kurier — recommended)

- `POST https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}` with
  `{"proofType": "groth16", "vkRegistered": true,
    "proofOptions": {"library": "snarkjs", "curve": "bn128"},
    "proofData": {"proof": ..., "publicSignals": ..., "vk": "<registeredVkHash>"}}`.
- Poll Submitted → IncludedInBlock → Finalized ("Safe to return as
  confirmed").
- `KURIER_API_KEY` comes from env; the user must obtain it from zkVerify —
  document how in the README. zkVerifyJS (Volta session, funded account) is
  the alternative.

## Registration (form, from the user's screenshot)

- Agent name "muse"; both arena tracks checked; Repository URL REQUIRED
  (public GitHub repo on the PERSONAL account — org repos unsupported);
  Agent Endpoint OPTIONAL.
- No mandatory file list for the repo URL; judges review the implementation.
  Prize eligibility requires a connected GitHub account + connected wallet
  address. There is NO official starter template repo.
- Whether a registered agent can be edited later, and the "3 agent slots"
  rule, are not stated anywhere readable.

## Other tracks (context only)

- Creator Track: manual review (technical substance, clarity, zkVerify
  relevance, originality); entries must include #AgentGames and tag
  @ZKVProtocol on X.
- Wildcard: public repo/demo/write-up + public HTTPS endpoint + use case;
  zkVerify optional.
