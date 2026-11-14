# PROVING.md — how Groth16 proving works here

Agent "muse" proves with the **platform's official circuits** (see
`SPEC.md`, `circuits/README.md`). No local Circom build, no trusted setup.

## Flow

```
platform envelope (task / turn)
  -> src/server.ts decides APPROVE/REJECT or HOLD/FORTIFY/EXTRACT
  -> src/proving.ts generateProof({track, circuitInputs, publicInputs})
      -> buildGatekeeperCircuitInputs() translates envelope-style inputs
         to the circuit's 13 named signals (drops proof_tx, converts hex,
         derives decision when absent, draws a random salt when absent)
      -> snarkjs.groth16.fullProve(inputs, <circuit>.wasm, <circuit>.zkey)
      -> { proof, publicSignals, circuit, circuitVersion, placeholder:false }
  -> server attaches proof + publicSignals to the response
  -> (optional) src/kurier.ts submits the proof to zkVerify via Kurier
```

`circuitVersion` is the published `vkHash` from `circuit-info.json`
(`gatekeeper 0x6b79…77b0`, `vfyPolicy 0x6c56…e047` — public constants).

## Local-only vs Kurier

- **Local-only (no `KURIER_API_KEY`):** the server still generates the
  Groth16 proof with snarkjs and returns it in the response
  (`proof` + `public_signals`). `proof_tx` stays `null`. This is the
  default until the user supplies a Kurier key.
- **Kurier (recommended):** `POST
  https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}` with
  `{"proofType": "groth16", "vkRegistered": true,
  "proofOptions": {"library": "snarkjs", "curve": "bn128"},
  "proofData": {"proof": ..., "publicSignals": ...,
  "vk": "<registeredVkHash>"}}`. Poll `Submitted -> IncludedInBlock ->
  Finalized` ("Safe to return as confirmed"). `KURIER_API_KEY` comes from
  env only — never commit it. zkVerifyJS (Volta session, funded account)
  is the alternative submission path.

## What a proof costs (time)

Measured on this VM (Node 24, snarkjs 0.7.6): gatekeeper `fullProve`
takes **~0.7–2 s** (witness ~0.2 s + proving), local `groth16.verify`
is instant. Well inside the platform's 60 s response budget. No
artificial timeout is set in `generateProof`; the server enforces the
60 s budget. (Note: the very first `require("snarkjs")` in a fresh
process is slow — tens of seconds on this VM — because the bundle is
large. The server imports it once at startup; warm proofs are the
~1 s figures above.)

**Worker-pool quirk (snarkjs/ffjavascript):** proving spawns a
`worker_threads` pool (`taskmanager.js` / `threadman.js`) that is never
terminated, so a process that proved anything never exits by itself
(verified: 4 dangling MessagePorts after one `fullProve`; `unref()` does
not help). The server is unaffected — it is long-lived and the workers
are reused across proofs. One-shot scripts must call `process.exit(0)`
after snarkjs work (`scripts/inspect-circuits.mjs` does this), and
`src/tests/proving.test.ts` exits the test child from an `after()` hook.

## Public-input counts (from the exported VKs — see INSPECT.md)

| circuit | public signals | total inputs | private inputs |
|---|---|---|---|
| gatekeeper | 13 | 13 | 1 (`salt` only) |
| vfyPolicy | 9 | 17 | 8 (names unknown) |

### Gatekeeper — FULLY recovered (13/13 names)

Inputs (circuit names): `registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, taskId, salt`.

- `decision`: `1` = APPROVE, `0` = REJECT. **Verified live:** an
  all-conditions-true assignment with `decision=1` produces a proof that
  verifies; `amount > maxTransfer` with `decision=0` also verifies; the
  same violation with `decision=1` fails at witness time (`Assert
  Failed. Error in template GatekeeperEvaluation_79 line: 102`) — the
  circuit asserts the decision equals the evaluated condition, so a wrong
  decision cannot produce a witness at all.
- Public-signal order: `[Poseidon(salt, taskId), registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
  Signal 0 is `Poseidon([salt, taskId])` — confirmed exactly with
  circomlibjs (changing `salt` or `taskId` changes it; changing vks or
  minimum does not).
- `salt` is the only private input: blinding for the task commitment.
  If the caller doesn't supply one, a fresh random 31-byte field element
  is drawn per proof.
- `registeredVkHash` / `proofVkHash` are the Poseidon hashes of the vks
  as supplied by the platform; the circuit only checks they are equal
  (hex envelope values are converted to field elements with BigInt).
- `taskId` encoding (**ASSUMPTION** — the platform's encoding is
  unpublished): an alphanumeric id such as `gk_24_9d1` is encoded as the
  big-endian integer of its UTF-8 bytes. The proof verifies
  cryptographically for any field element; only the platform's reading of
  public signal 12 depends on this encoding matching theirs. If the
  platform publishes the encoding, update
  `buildGatekeeperCircuitInputs()` and this doc — do not guess further.
- `proof_tx` is NOT a circuit input and is dropped by the translator.

### Steal the VFY (vfyPolicy) — INCOMPLETE, proofs blocked (honest error)

Recovered (9/17): `commitment, matchId, turnNumber, selfBalance,
opponentBalance, action, amount, circuitVersion, salt`. These map to the
8 published `publicInputsHash` fields (`strategyCommitment.hash`,
`matchId`, `turn`, `selfBalance`, `opponentBalance`, `action`, `amount`,
`circuitVersion "v1"=1`) plus `salt` — but the remaining **8 private
input names are unknown** and cannot be guessed. `generateProof("steal")`
therefore throws a clear error (`Steal (vfyPolicy) circuit input signal
names are not fully published…`) instead of faking a proof. The server
maps this to `proof: null`, and the Steal response still carries the
`publicInputsHash` (see below) — a hash the platform can check without a
proof.

### Steal publicInputsHash (PUBLISHED — implemented exactly)

`computeStealPublicInputsHash()` in `src/proving.ts`: keccak256 over 8
fields, each 32-byte big-endian, in SPEC.md order:
`strategyCommitment.hash`, `matchId` (hyphens stripped, as integer),
`turn`, `selfBalance`, `opponentBalance`, `action` (HOLD=0, FORTIFY=1,
EXTRACT=2), `amount` (0 for HOLD/FORTIFY — forced), `circuitVersion`
`"v1"` (=1). Returns `0x…` hex. Verified against independent
pycryptodome keccak vectors in `src/tests/proving.test.ts` (3 known
answers, including an all-zero field set).

## TBD (not published — do NOT invent)

- vfyPolicy's 8 private input names (blocks Steal proofs until published).
- The platform's `taskId` field-element encoding (assumption documented
  above; proof validity does not depend on it).
- Gatekeeper's ordered `public_signals` **semantics** beyond the verified
  order above (the order itself is now verified live, not TBD).
- Whether a registered agent can be edited later / the "3 agent slots"
  rule (registration, not proving — see SPEC.md).

## Re-downloading artifacts

```sh
bash scripts/download-artifacts.sh   # idempotent; verifies sizes; writes CHECKSUMS.txt
node scripts/inspect-circuits.mjs    # re-export VKs, regenerate INSPECT.md
node scripts/probe-input-names.mjs   # re-probe input names, regenerate PROBE.md
```

## When the guide publishes more

If a new `circuit-info.json` appears (new circuits / new vkHashes /
vfyPolicy input names): re-run the three scripts above, update the
`PUBLISHED_VK_HASH` constants and `PLATFORM_VK_HASH_*` in `.env.example`,
extend `TRACK_FILES` / the translator in `src/proving.ts`, add the
recovered names to `PROBE.md`, and re-run `npm test`. The swap is
config + constants — no new ceremony: the platform publishes the
artifacts, so we never run our own trusted setup.

## Never

- Never fake a proof: `generateProof` throws rather than returning a
  placeholder (the `placeholder` field exists in the result type only so
  the server can distinguish; this module always returns
  `placeholder: false`).
- Never guess input names: every name in the translator was verified by
  a live witness/proof round-trip. An unverified name is a loud error.
- Never commit secrets: `AGENT_GAMES_HMAC_SECRET` and `KURIER_API_KEY`
  come from env / `fly secrets set` only. The vkHashes are public
  platform constants and are safe to commit.
