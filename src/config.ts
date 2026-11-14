/**
 * Environment configuration for the Agent Games agent "muse".
 *
 * All secrets come from env only. This module NEVER logs secret values —
 * it logs only whether a secret is set, never its content.
 *
 * SPEC.md (authoritative, read 2026-11-15):
 * - HMAC: header `x-agent-games-signature` (inbound AND outbound),
 *   HMAC-SHA256 hex over the RAW body, secret `AGENT_GAMES_HMAC_SECRET`
 *   (32-byte random, shown once at registration/rotation).
 * - Kurier: POST https://api.kurier.xyz/api/v1/submit-proof/${key}.
 */

export interface AgentConfig {
  port: number;
  host: string;
  agentName: string;
  /** HMAC shared secret provisioned by the platform (Rotate Secret). */
  hmacSecret: string | undefined;
  /** Accepted incoming signature headers (exact spec default). */
  hmacHeaders: string[];
  /** HMAC algorithm — the platform's is sha256. */
  hmacAlgorithm: string;
  /** Per-request response budget in ms; must stay below the 60 s deadline. */
  responseTimeoutMs: number;
  /** Optional Kurier (zkVerify relayer) API key. */
  kurierApiKey: string | undefined;
  /** Kurier API base URL. */
  kurierApiUrl: string;
  /** Kurier job-status path (ASSUMPTION — not published; see kurier.ts). */
  kurierStatusPath: string;
  /** Platform-published VK hash for the Gatekeeper circuit. */
  platformVkHashGatekeeper: string;
  /** Platform-published VK hash for the VFY Policy circuit. */
  platformVkHashVfyPolicy: string;
  /** Directory holding circuit artifacts (wasm/zkey). */
  circuitDir: string;
  /** Optional path to the platform's registered VK file. */
  platformVkPath: string | undefined;
  /** Optional registered strategy-commitment hash for Steal the VFY. */
  strategyCommitment: string | undefined;
  /** True when the operator explicitly allowed running without a secret. */
  allowNoSecret: boolean;
}

export const DEFAULT_PORT = 3000;
export const DEFAULT_HOST = "0.0.0.0";
export const DEFAULT_AGENT_NAME = "muse";
/** Exact per SPEC.md: one header, inbound and outbound. */
export const DEFAULT_HMAC_HEADERS = ["x-agent-games-signature"];
export const DEFAULT_HMAC_ALGORITHM = "sha256";
/** 55 s — inside the platform's 60 s hard deadline, with headroom. */
export const DEFAULT_RESPONSE_TIMEOUT_MS = 55000;
/** Exact per SPEC.md. */
export const DEFAULT_KURIER_API_URL = "https://api.kurier.xyz";
/** ASSUMPTION: Kurier job-status path is NOT published; override via env. */
export const DEFAULT_KURIER_STATUS_PATH = "/api/v1/proof-status";
export const DEFAULT_VK_HASH_GATEKEEPER =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
export const DEFAULT_VK_HASH_VFYPOLICY =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";
export const DEFAULT_CIRCUIT_DIR = "./circuits/artifacts";

function parseIntEnv(
  raw: string | undefined,
  fallback: number,
  name: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`Invalid ${name}: ${JSON.stringify(raw)}`);
  }
  return n;
}

function parseListEnv(
  raw: string | undefined,
  fallback: string[],
): string[] {
  if (raw === undefined || raw.trim() === "") return [...fallback];
  return raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
}

/**
 * Parse config from env (defaults to process.env).
 * @throws if AGENT_GAMES_HMAC_SECRET is missing and ALLOW_NO_SECRET is
 *         not "1", or if RESPONSE_TIMEOUT_MS is >= 60000 (would breach
 *         the platform deadline).
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
): AgentConfig {
  const responseTimeoutMs = parseIntEnv(
    env.RESPONSE_TIMEOUT_MS,
    DEFAULT_RESPONSE_TIMEOUT_MS,
    "RESPONSE_TIMEOUT_MS",
  );
  if (responseTimeoutMs >= 60000) {
    throw new Error(
      "RESPONSE_TIMEOUT_MS must be < 60000 (platform hard deadline is 60s)",
    );
  }

  const hmacSecret = env.AGENT_GAMES_HMAC_SECRET;
  const allowNoSecret = env.ALLOW_NO_SECRET === "1";

  if (!hmacSecret && !allowNoSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is required in production. " +
        "Set it to the platform-provisioned secret, or set ALLOW_NO_SECRET=1 " +
        "for local development only.",
    );
  }
  if (!hmacSecret && allowNoSecret) {
    console.warn(
      "[config] WARNING: running WITHOUT an HMAC secret " +
        "(ALLOW_NO_SECRET=1). Every request will be rejected as unsigned " +
        "unless the secret is set. Do NOT use this in production.",
    );
  }

  return {
    port: parseIntEnv(env.PORT, DEFAULT_PORT, "PORT"),
    host: env.HOST ?? DEFAULT_HOST,
    agentName: env.AGENT_NAME ?? DEFAULT_AGENT_NAME,
    hmacSecret,
    hmacHeaders: parseListEnv(env.HMAC_HEADER, DEFAULT_HMAC_HEADERS),
    hmacAlgorithm: (env.HMAC_ALGORITHM ?? DEFAULT_HMAC_ALGORITHM)
      .trim()
      .toLowerCase(),
    responseTimeoutMs,
    kurierApiKey: env.KURIER_API_KEY || undefined,
    kurierApiUrl: env.KURIER_API_URL?.trim() || DEFAULT_KURIER_API_URL,
    kurierStatusPath:
      env.KURIER_STATUS_PATH?.trim() || DEFAULT_KURIER_STATUS_PATH,
    platformVkHashGatekeeper:
      env.PLATFORM_VK_HASH_GATEKEEPER?.trim() ||
      DEFAULT_VK_HASH_GATEKEEPER,
    platformVkHashVfyPolicy:
      env.PLATFORM_VK_HASH_VFYPOLICY?.trim() ||
      DEFAULT_VK_HASH_VFYPOLICY,
    circuitDir: env.CIRCUIT_DIR?.trim() || DEFAULT_CIRCUIT_DIR,
    platformVkPath: env.PLATFORM_VK_PATH?.trim() || undefined,
    strategyCommitment: env.STRATEGY_COMMITMENT?.trim() || undefined,
    allowNoSecret,
  };
}
