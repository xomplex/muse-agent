/**
 * Minimal ambient declaration for `snarkjs` (no @types/snarkjs exists).
 * This shim exists only so `tsc` can compile src/proving.ts, which
 * imports snarkjs. It does not change runtime behaviour.
 */
declare module "snarkjs";
