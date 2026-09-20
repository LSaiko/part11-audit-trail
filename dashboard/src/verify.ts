// Client-side mirror of crypto/hashing.py + app/verifier.py so the Pages demo (no server) can
// genuinely verify the 21 CFR Part 11 hash chain (11.10(e)). Uses Web Crypto sha256 only; the
// canonicalisation (Unit Separator delimiter, field order, sorted-key compact JSON) must match
// the Python side byte for byte -- scripts/check-seed.mjs proves it against tests/seed_parity.json.
import type { AuditEvent, IntegrityCheckResult } from "./types.ts";

export const GENESIS_HASH = "0".repeat(64);
export const DELIMITER = "\x1f"; // ASCII Unit Separator, same as crypto/hashing.py

const enc = new TextEncoder();

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** crypto/hashing.py entry_hash: fields joined by \x1f in this exact order. */
export function entryHash(
  beforeHash: string,
  actor: string,
  action: string,
  recordId: string,
  timestampIso: string,
  recordType = "",
  afterHash = "",
): Promise<string> {
  return sha256([beforeHash, actor, action, recordType, recordId, timestampIso, afterHash].join(DELIMITER));
}

/** crypto/hashing.py canonical_json: json.dumps(sort_keys=True, separators=(",", ":")) incl.
 *  ensure_ascii (every char outside 0x20-0x7e is \uXXXX-escaped, as Python does).
 *  // ponytail: numbers are emitted as JS prints them (1.0 -> "1", Python -> "1.0"); keep
 *  // record content to strings, integers, booleans, null, arrays and objects. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${canonicalJson(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(value).replace(/[-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export const recordHash = (content: unknown): Promise<string> => sha256(canonicalJson(content));

/** app/verifier.py verify_chain: recompute every entry_hash and check each before_hash links to
 *  its predecessor; first_broken_link is the 0-based index of the first failing entry. */
export async function verifyChain(events: readonly AuditEvent[]): Promise<IntegrityCheckResult> {
  let expectedBefore = GENESIS_HASH;
  let firstBroken: number | null = null;
  for (const [index, e] of events.entries()) {
    const recomputed = await entryHash(e.before_hash, e.actor, e.action, e.record_id, e.timestamp, e.record_type, e.after_hash ?? "");
    if (e.before_hash !== expectedBefore || e.entry_hash !== recomputed) {
      firstBroken = index;
      break;
    }
    expectedBefore = e.entry_hash;
  }
  return {
    checked_at: new Date().toISOString(),
    chain_valid: firstBroken === null,
    first_broken_link: firstBroken,
    total_events_checked: events.length,
  };
}
