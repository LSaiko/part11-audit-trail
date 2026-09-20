import { buildSeed, tamper, verifySeedSignature, type SeedState } from "./seed.ts";
import type { AuditEvent, AuditTrail, ESignature, IntegrityCheckResult, SignatureVerification } from "./types.ts";
import { verifyChain } from "./verify.ts";

export interface Backend {
  readonly mode: "api" | "seed";
  events(): Promise<AuditEvent[]>;
  trail(recordId: string): Promise<AuditTrail>;
  signatures(): Promise<ESignature[]>;
  verifyChain(): Promise<IntegrityCheckResult>;
  verifySignature(id: string): Promise<SignatureVerification>;
}

const API = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8011";

async function call<T>(path: string): Promise<T> {
  const r = await fetch(`${API}${path}`);
  if (!r.ok) throw new Error(`${r.status} ${path}: ${((await r.json()) as { detail?: string }).detail ?? ""}`);
  return (await r.json()) as T;
}

/** Live mode: the server is the verifier (app/verifier.py); the dashboard only renders. */
const remote: Backend = {
  mode: "api",
  events: () => call("/events"),
  trail: (id) => call(`/audit-trail/${encodeURIComponent(id)}`),
  signatures: () => call("/signatures"),
  verifyChain: () => call("/verify-chain"),
  verifySignature: (id) => call(`/verify-signature/${encodeURIComponent(id)}`),
};

/** Seed mode: same contract, verified in the browser by verify.ts (mirror of app/verifier.py). */
export function localBackend(state: SeedState): Backend {
  return {
    mode: "seed",
    events: async () => state.events,
    trail: async (id) => {
      const events = state.events.filter((e) => e.record_id === id);
      if (!events.length) throw new Error(`404 no audit events for record ${id}`);
      return { record_id: id, events, integrity: await verifyChain(state.events) };
    },
    signatures: async () => state.signatures,
    verifyChain: () => verifyChain(state.events),
    verifySignature: (id) => {
      const sig = state.signatures.find((s) => s.id === id);
      if (!sig) throw new Error(`404 unknown signature ${id}`);
      return verifySeedSignature(state, sig);
    },
  };
}

export interface Connection { intact: Backend; tampered: Backend | null }

/** Seed when built for Pages (non-root base) or when the API does not answer /health. */
export async function connect(): Promise<Connection> {
  if (import.meta.env.BASE_URL === "/") {
    try {
      const r = await fetch(`${API}/health`);
      if (r.ok) return { intact: remote, tampered: null };
    } catch { /* fall through */ }
  }
  const seed = await buildSeed();
  return { intact: localBackend(seed), tampered: localBackend(tamper(seed)) };
}
