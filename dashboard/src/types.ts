// Mirrors schemas/models.py (Pydantic v2). Field names and hash semantics are identical so the
// client-side verifier in verify.ts can re-check the same chain the server checks.

export interface AuditEvent {
  id: string;
  timestamp: string; // ISO 8601, server-set UTC (Contemporaneous)
  actor: string;
  action: string;
  record_type: string;
  record_id: string;
  before_hash: string;
  after_hash: string | null;
  entry_hash: string;
}

export type SignatureMeaning = "reviewed" | "approved" | "authored" | "rejected";

export interface ESignature {
  id: string;
  signer: string;
  signed_record_id: string;
  signed_record_hash: string;
  timestamp: string;
  meaning: SignatureMeaning;
  signature_method: string;
  signature_value: string;
}

export interface SignatureVerification {
  signature_id: string;
  record_hash_matches: boolean;
  signature_valid: boolean;
  captured_hash: string;
  current_hash: string;
  checked_at: string;
}

export interface IntegrityCheckResult {
  checked_at: string;
  chain_valid: boolean;
  first_broken_link: number | null;
  total_events_checked: number;
}

export interface AuditTrail {
  record_id: string;
  events: AuditEvent[];
  integrity: IntegrityCheckResult;
}
