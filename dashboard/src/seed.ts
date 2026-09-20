// Seed shown when VITE_BASE is non-root (GitHub Pages) or the API is unreachable: a synthetic
// but genuinely valid 21 CFR Part 11 trail. Every entry_hash / after_hash below is computed at
// load time with verify.ts (the same canonicalisation as crypto/hashing.py), so the intact seed
// passes the real verifier and the tampered copy fails it for the real reason.
import type { AuditEvent, ESignature, SignatureVerification } from "./types.ts";
import { GENESIS_HASH, canonicalJson, entryHash, recordHash } from "./verify.ts";

type Content = Record<string, unknown>;
interface Step { actor: string; action: string; record_type: string; record_id: string; content?: Content; ts: string }

const SOP_V1: Content = { title: "Equipment cleaning procedure", revision: 3, status: "draft", steps: ["rinse", "detergent", "final rinse", "dry"] };
const SOP_V2: Content = { ...SOP_V1, revision: 4, status: "effective", steps: ["rinse", "detergent", "final rinse", "dry", "visual inspection"] };
const CAPA_V1: Content = { title: "Bracket torque out of spec on line 3", severity: "major", status: "open" };
const CAPA_V2: Content = { ...CAPA_V1, status: "capa_assigned", owner: "bob" };
const CAPA_V3: Content = { ...CAPA_V2, status: "effectiveness_pending", check_due: "2026-10-18" };
const DHF_V1: Content = { text: "The pump shall alarm within 2 s of a door-open event", risk_control: true, verified: false };
const DHF_V2: Content = { ...DHF_V1, verified: true, test_ref: "TP-114" };
const DHF_V3: Content = { ...DHF_V2, reviewed_by: "dave" };

// 12 steps across 3 records; #5 (index 4) is the row the tamper toggle rewrites.
const STEPS: Step[] = [
  { actor: "alice", action: "create", record_type: "sop", record_id: "SOP-017", content: SOP_V1, ts: "2026-09-14T08:02:11+00:00" },
  { actor: "alice", action: "create", record_type: "capa", record_id: "CAPA-0042", content: CAPA_V1, ts: "2026-09-14T09:15:40+00:00" },
  { actor: "bob", action: "create", record_type: "dhf_requirement", record_id: "DHF-REQ-3", content: DHF_V1, ts: "2026-09-15T10:30:05+00:00" },
  { actor: "bob", action: "update", record_type: "capa", record_id: "CAPA-0042", content: CAPA_V2, ts: "2026-09-15T14:47:59+00:00" },
  { actor: "alice", action: "update", record_type: "sop", record_id: "SOP-017", content: SOP_V2, ts: "2026-09-16T07:58:23+00:00" },
  { actor: "carol", action: "update", record_type: "dhf_requirement", record_id: "DHF-REQ-3", content: DHF_V2, ts: "2026-09-16T11:20:00+00:00" },
  { actor: "bob", action: "esign:reviewed", record_type: "sop", record_id: "SOP-017", content: SOP_V2, ts: "2026-09-16T15:05:44+00:00" },
  { actor: "alice", action: "esign:approved", record_type: "sop", record_id: "SOP-017", content: SOP_V2, ts: "2026-09-17T08:41:12+00:00" },
  { actor: "carol", action: "update", record_type: "capa", record_id: "CAPA-0042", content: CAPA_V3, ts: "2026-09-17T13:09:37+00:00" },
  { actor: "bob", action: "esign:approved", record_type: "capa", record_id: "CAPA-0042", content: CAPA_V3, ts: "2026-09-18T09:26:50+00:00" },
  { actor: "dave", action: "update", record_type: "dhf_requirement", record_id: "DHF-REQ-3", content: DHF_V3, ts: "2026-09-18T16:12:08+00:00" },
  { actor: "carol", action: "esign:reviewed", record_type: "dhf_requirement", record_id: "DHF-REQ-3", content: DHF_V3, ts: "2026-09-19T10:00:31+00:00" },
];
const SIGNED_STEP = 7; // alice's esign:approved on SOP-017 -> the one seeded ESignature

export interface SeedRecord { record_type: string; content: Content }
export interface Signer { verify(payload: string, signatureB64: string): Promise<boolean> }
export interface SeedState {
  events: AuditEvent[];
  records: Record<string, SeedRecord>;
  signatures: ESignature[];
  signer: Signer | null; // null: this browser has no Web Crypto Ed25519 (signature reported as unverifiable)
}

/** app/signatures.py signature_payload: canonical JSON of every field except signature_value. */
export function signaturePayload(sig: ESignature): string {
  const { signature_value: _omit, ...rest } = sig;
  return canonicalJson(rest);
}

const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const enc = new TextEncoder();

// ponytail: an ephemeral in-browser Ed25519 key stands in for the server key (same role as the
// AUDIT_SIGNING_KEY-unset warning path). Browsers without Web Crypto Ed25519 get signer=null.
async function makeSigner(): Promise<{ sign(payload: string): Promise<string>; signer: Signer } | null> {
  try {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    return {
      sign: async (payload) => b64(await crypto.subtle.sign("Ed25519", kp.privateKey, enc.encode(payload))),
      signer: { verify: (payload, sig) => crypto.subtle.verify("Ed25519", kp.publicKey, unb64(sig), enc.encode(payload)) },
    };
  } catch {
    return null;
  }
}

export async function buildSeed(): Promise<SeedState> {
  const events: AuditEvent[] = [];
  const records: Record<string, SeedRecord> = {};
  let before = GENESIS_HASH;
  for (const [i, s] of STEPS.entries()) {
    const after = s.content ? await recordHash(s.content) : null;
    const entry = await entryHash(before, s.actor, s.action, s.record_id, s.ts, s.record_type, after ?? "");
    events.push({
      id: `seed-${String(i + 1).padStart(3, "0")}`,
      timestamp: s.ts,
      actor: s.actor,
      action: s.action,
      record_type: s.record_type,
      record_id: s.record_id,
      before_hash: before,
      after_hash: after,
      entry_hash: entry,
    });
    if (s.content && !s.action.startsWith("esign:")) records[s.record_id] = { record_type: s.record_type, content: s.content };
    before = entry;
  }
  const signed = events[SIGNED_STEP];
  const keys = await makeSigner();
  const unsigned: ESignature = {
    id: "sig-seed-001",
    signer: signed.actor,
    signed_record_id: signed.record_id,
    signed_record_hash: signed.after_hash!,
    timestamp: signed.timestamp,
    meaning: "approved",
    signature_method: keys ? "ed25519_webcrypto_demo" : "unverifiable_in_this_browser",
    signature_value: "",
  };
  const signature_value = keys ? await keys.sign(signaturePayload(unsigned)) : "";
  return { events, records, signatures: [{ ...unsigned, signature_value }], signer: keys?.signer ?? null };
}

/** What an attacker with database access would leave behind: entry #5's actor rewritten in
 *  place (its stored entry_hash no longer matches), and SOP-017 edited after it was signed. */
export function tamper(seed: SeedState): SeedState {
  const events = seed.events.map((e, i) => (i === 4 ? { ...e, actor: "mallory" } : e));
  const sop = seed.records["SOP-017"];
  const records = { ...seed.records, "SOP-017": { ...sop, content: { ...sop.content, status: "obsolete", revision: 5 } } };
  return { ...seed, events, records };
}

export async function verifySeedSignature(seed: SeedState, sig: ESignature): Promise<SignatureVerification> {
  const current = await recordHash(seed.records[sig.signed_record_id].content);
  return {
    signature_id: sig.id,
    record_hash_matches: sig.signed_record_hash === current,
    signature_valid: seed.signer ? await seed.signer.verify(signaturePayload(sig), sig.signature_value) : true,
    captured_hash: sig.signed_record_hash,
    current_hash: current,
    checked_at: new Date().toISOString(),
  };
}
