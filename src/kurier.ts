/**
 * Kurier proof submission (zkVerify relayer, REST) — exact per SPEC.md.
 *
 *   POST https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}
 *   {"proofType":"groth16","vkRegistered":true,
 *    "proofOptions":{"library":"snarkjs","curve":"bn128"},
 *    "proofData":{"proof":...,"publicSignals":...,"vk":"<registeredVkHash>"}}
 *
 * Poll Submitted → IncludedInBlock → Finalized ("Safe to return as
 * confirmed").
 *
 * ASSUMPTION (the guide publishes the submit endpoint but NOT the
 * job-status path): polling uses GET
 * `${KURIER_API_URL}${KURIER_STATUS_PATH}/${jobId}` with the API key as
 * an `x-api-key` header. The path is configurable via KURIER_STATUS_PATH
 * (default "/api/v1/proof-status") so a wrong guess is a one-line fix.
 * A non-Finalized or erroring submission is reported, never faked —
 * proofTx stays null.
 *
 * The API key is sent in the URL path (per spec) and is NEVER logged.
 * Polling is bounded (~20 s) so the 60 s platform budget still holds.
 */
import type { SubmitProofRequest, SubmitProofResult } from "./types";

export const KURIER_SUBMIT_PATH = "/api/v1/submit-proof";
/** Total budget for submit + poll, ms. */
export const KURIER_TOTAL_TIMEOUT_MS = 20000;
/** Delay between status polls, ms. */
export const KURIER_POLL_INTERVAL_MS = 2000;

export interface KurierClientOptions {
  apiKey?: string;
  apiUrl: string;
  /** Job-status path; see the ASSUMPTION note above. */
  statusPath?: string;
}

export class KurierNotConfiguredError extends Error {
  constructor() {
    super(
      "Kurier not configured: set KURIER_API_KEY (and optionally KURIER_API_URL)",
    );
    this.name = "KurierNotConfiguredError";
  }
}

/** Pick the job id out of a Kurier response, tolerating field spellings. */
function extractJobId(body: Record<string, unknown>): string | undefined {
  const v =
    body.jobId ?? body.job_id ?? body.id ?? body.proofId ?? body.proof_id;
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function extractProofTx(body: Record<string, unknown>): string | null {
  const v = body.proofTx ?? body.proof_tx ?? body.txHash ?? body.tx_hash;
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Submit a proof for on-chain verification and wait until it is
 * Finalized. Returns the on-chain proof tx when Finalized.
 * @throws KurierNotConfiguredError when no API key is configured.
 * @throws on network/HTTP errors or when the job does not finalize
 *         within KURIER_TOTAL_TIMEOUT_MS.
 */
export async function submitProof(
  req: SubmitProofRequest,
  opts: KurierClientOptions,
): Promise<SubmitProofResult> {
  if (!opts.apiKey) throw new KurierNotConfiguredError();
  const base = opts.apiUrl.replace(/\/+$/, "");
  const statusPath = opts.statusPath ?? "/api/v1/proof-status";
  const deadline = Date.now() + KURIER_TOTAL_TIMEOUT_MS;

  const submitRes = await fetch(
    `${base}${KURIER_SUBMIT_PATH}/${encodeURIComponent(opts.apiKey)}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          proof: req.proof,
          publicSignals: req.publicSignals,
          vk: req.vkHash,
        },
      }),
      signal: AbortSignal.timeout(KURIER_TOTAL_TIMEOUT_MS),
    },
  );
  if (!submitRes.ok) {
    throw new Error(`Kurier submit failed: HTTP ${submitRes.status}`);
  }
  const submitted = (await submitRes.json()) as Record<string, unknown>;
  const jobId = extractJobId(submitted);
  const submitStatus =
    typeof submitted.status === "string" ? submitted.status : undefined;
  const submitTx = extractProofTx(submitted);
  if (submitStatus === "Finalized") {
    return { jobId: jobId ?? "", proofTx: submitTx, status: "Finalized" };
  }
  if (!jobId) {
    throw new Error("Kurier submit response has no job id");
  }

  // Poll until Finalized (or inclusion, as a last resort before timeout).
  let status = submitStatus ?? "Submitted";
  let proofTx: string | null = submitTx;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(
        `${base}${statusPath}/${encodeURIComponent(jobId)}`,
        {
          method: "GET",
          headers: { "x-api-key": opts.apiKey },
          signal: AbortSignal.timeout(KURIER_POLL_INTERVAL_MS + 1000),
        },
      );
      if (res.ok) {
        const job = (await res.json()) as Record<string, unknown>;
        if (typeof job.status === "string") status = job.status;
        proofTx = extractProofTx(job) ?? proofTx;
        if (status === "Finalized") {
          return { jobId, proofTx, status };
        }
      }
    } catch {
      // Transient poll failure: keep polling until the deadline.
    }
    await new Promise((r) => setTimeout(r, KURIER_POLL_INTERVAL_MS));
  }
  return { jobId, proofTx, status: `${status} (poll timeout)` };
}
