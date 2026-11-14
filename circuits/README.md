# circuits/ — official zkVerify Agent Games artifacts (NOT ours)

These are the **PLATFORM's** published Groth16 circuits for Season 01, not
circuits we wrote. No Circom source was written here and no trusted setup
was run — the platform publishes the proving artifacts and we prove locally
with snarkjs (see `../SPEC.md` and `../PROVING.md`).

## Source

Circuit-info API: https://agentgames.zkverify.io/api/circuit-info

| circuit | vkHash (published, public constant) | wasm | zkey |
|---|---|---|---|
| gatekeeper | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey |
| vfyPolicy | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` | https://agentgames.zkverify.io/circuits/vfy-policy.wasm | https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey |

Each circuit's `vkHash` is registered on zkVerify mainnet — copy it when
submitting proofs via Kurier (it is the `circuitVersion` in proof payloads).

## What's in circuits/artifacts/

- `gatekeeper.wasm` (1,755,820 B), `gatekeeper_final.zkey` (309,750 B)
- `vfy-policy.wasm` (2,991,212 B), `vfy-policy_final.zkey` (810,586 B)
- `circuit-info.json` — the API response above (519 B)
- `CHECKSUMS.txt` — sha256 of the five files above
- `gatekeeper.vkey.json`, `vfy-policy.vkey.json` — verification keys
  exported with `snarkjs zkey export verificationkey`
- `INSPECT.md` — per-circuit protocol/curve/public-input counts
- `PROBE.md` — input-signal-name recovery report

## Public inputs

From the exported VKs (`VK.IC.length - 1`):

- **gatekeeper: 13 public signals** (12 public inputs + 1 Poseidon task
  commitment; `salt` is the only private input). Input names were
  RECOVERED (13/13) — see `PROBE.md`. Public-signal order:
  `[Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`.
- **vfyPolicy: 9 public signals**, 17 total inputs (9 public + 8 private).
  Input names only PARTIALLY recovered (9/17) — see `PROBE.md`.
  The remaining 8 private input names are NOT published anywhere readable.

**TBD / not published:** the platform publishes no circuit source and no
input-name list. Names above were recovered by probing the wasm with the
FNV-1a oracle in circom_runtime (`../scripts/probe-input-names.mjs`);
they are NOT guessed. If the platform publishes more (new circuits, new
vkHashes, the vfyPolicy private inputs), re-run the scripts below and
update `PROVING.md` — do not invent replacements.

## Scripts

- `../scripts/download-artifacts.sh` — (re-)download the four artifacts +
  `circuit-info.json`, verify sizes, write `CHECKSUMS.txt`. Idempotent
  (skips files that already exist with the right size).
- `../scripts/inspect-circuits.mjs` — export VKs, print public-input
  counts, regenerate `INSPECT.md`.
- `../scripts/probe-input-names.mjs` — probe the wasm for input signal
  names, regenerate `PROBE.md`.

## If the official artifacts turn out unusable

Document it here and in `PROVING.md` instead of inventing a replacement
circuit. The platform's circuits are the only ones the platform will
verify — a local substitute would be unverifiable by the platform and is
not a fallback.
