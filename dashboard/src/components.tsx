import type { AuditEvent, AuditTrail, ESignature, IntegrityCheckResult, SignatureVerification } from "./types.ts";

export const CYAN = "#22d3ee"; // valid / ok
export const ORANGE = "#f97316"; // broken / mismatch
export const SLATE = "#94a3b8"; // neutral

/** First 8 hex chars, full digest on hover (title) -- the table stays readable at 64-char hashes. */
export const Hash = ({ value }: { value: string | null }) =>
  value ? <code className="hash" title={value}>{value.slice(0, 8)}</code> : <span className="muted">-</span>;

// ---- chain integrity banner --------------------------------------------------------------------

export function Banner({ integrity, events }: { integrity: IntegrityCheckResult; events: AuditEvent[] }) {
  if (integrity.chain_valid) {
    return (
      <div className="banner ok" role="status">
        <strong>CHAIN INTACT</strong> · {integrity.total_events_checked} events verified
        <span className="muted small"> · every entry_hash recomputed and every before_hash linked back to genesis (11.10(e))</span>
      </div>
    );
  }
  const k = integrity.first_broken_link ?? 0;
  const culprit = events[k];
  return (
    <div className="banner broken" role="alert">
      <strong>CHAIN BROKEN at entry #{k + 1}</strong>
      {culprit ? <> · {culprit.record_id} · stored entry_hash <Hash value={culprit.entry_hash} /> does not match the recomputed fields</> : null}
      <span className="muted small"> · entries from #{k + 1} onward cannot be trusted; the Documenter reports this finding and never repairs it</span>
    </div>
  );
}

// ---- record selector ---------------------------------------------------------------------------

export function RecordList({ events, selected, onSelect }: { events: AuditEvent[]; selected: string | null; onSelect: (id: string) => void }) {
  const ids = [...new Set(events.map((e) => e.record_id))];
  return (
    <nav aria-label="Records">
      <h2>Records</h2>
      {ids.map((id) => {
        const mine = events.filter((e) => e.record_id === id);
        return (
          <button key={id} className={`record${id === selected ? " active" : ""}`} onClick={() => onSelect(id)} aria-pressed={id === selected}>
            <code>{id}</code>
            <span className="muted small">{mine[0].record_type} · {mine.length} events</span>
          </button>
        );
      })}
    </nav>
  );
}

// ---- audit trail table -------------------------------------------------------------------------

export function TrailTable({ trail, indexOf }: { trail: AuditTrail; indexOf: Map<string, number> }) {
  const broken = trail.integrity.first_broken_link;
  return (
    <table>
      <thead>
        <tr><th>#</th><th>timestamp (UTC)</th><th>actor</th><th>action</th><th>before_hash → entry_hash</th><th>after_hash</th><th>status</th></tr>
      </thead>
      <tbody>
        {trail.events.map((e) => {
          const k = indexOf.get(e.id) ?? -1;
          const isBroken = broken !== null && k === broken;
          const after = broken !== null && k > broken;
          return (
            <tr key={e.id} className={isBroken ? "row-broken" : after ? "row-after" : ""}>
              <td>{k + 1}</td>
              <td className="mono">{e.timestamp.replace("T", " ").replace("+00:00", "")}</td>
              <td>{e.actor}</td>
              <td><code>{e.action}</code></td>
              <td><Hash value={e.before_hash} /> → <Hash value={e.entry_hash} /></td>
              <td><Hash value={e.after_hash} /></td>
              <td className="small">{isBroken ? <span className="pill broken">HASH MISMATCH</span> : after ? <span className="muted">after break</span> : <span className="ok">linked</span>}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---- signatures panel --------------------------------------------------------------------------

export function pillFor(v: SignatureVerification | undefined): { text: string; ok: boolean } {
  if (!v) return { text: "CHECKING…", ok: true };
  if (!v.signature_valid) return { text: "SIGNATURE INVALID", ok: false };
  if (!v.record_hash_matches) return { text: "RECORD CHANGED SINCE SIGNING", ok: false };
  return { text: "VERIFIED", ok: true };
}

export function SignaturesPanel({ sigs, checks }: { sigs: ESignature[]; checks: Record<string, SignatureVerification> }) {
  return (
    <section>
      <h2>Electronic signatures <span className="muted small">(11.50 meaning · 11.70 record linking)</span></h2>
      {sigs.length === 0 ? <p className="muted">No signatures on this record.</p> : (
        <table>
          <thead><tr><th>signer</th><th>meaning</th><th>signed at (UTC)</th><th>captured hash</th><th>current hash</th><th>status</th></tr></thead>
          <tbody>
            {sigs.map((s) => {
              const v = checks[s.id];
              const pill = pillFor(v);
              return (
                <tr key={s.id}>
                  <td>{s.signer}<div className="muted small">{s.signature_method}</div></td>
                  <td><code>{s.meaning}</code></td>
                  <td className="mono">{s.timestamp.replace("T", " ").replace("+00:00", "")}</td>
                  <td><Hash value={s.signed_record_hash} /></td>
                  <td><Hash value={v?.current_hash ?? null} /></td>
                  <td><span className={`pill ${pill.ok ? "ok" : "broken"}`}>{pill.text}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
