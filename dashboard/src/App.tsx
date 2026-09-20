import { useEffect, useState } from "react";
import { connect, type Backend, type Connection } from "./api.ts";
import { Banner, RecordList, SignaturesPanel, TrailTable } from "./components.tsx";
import type { AuditEvent, AuditTrail, ESignature, SignatureVerification } from "./types.ts";
import "./app.css";

const tamperFromUrl = () => new URLSearchParams(window.location.search).get("tamper") === "1";

export default function App() {
  const [conn, setConn] = useState<Connection | null>(null);
  const [tampered, setTampered] = useState(tamperFromUrl); // ?tamper=1 pre-enables the toggle
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [sigs, setSigs] = useState<ESignature[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null); // ponytail: no router
  const [trail, setTrail] = useState<AuditTrail | null>(null);
  const [checks, setChecks] = useState<Record<string, SignatureVerification>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { connect().then(setConn, (e: unknown) => setError(String(e))); }, []);

  const api: Backend | null = conn ? (tampered && conn.tampered ? conn.tampered : conn.intact) : null;

  useEffect(() => {
    if (!api) return;
    let live = true;
    (async () => {
      try {
        const [ev, sg] = await Promise.all([api.events(), api.signatures()]);
        if (!live) return;
        setEvents(ev);
        setSigs(sg);
        const id = selectedId && ev.some((e) => e.record_id === selectedId) ? selectedId : (ev[0]?.record_id ?? null);
        setSelectedId(id);
        if (!id) { setTrail(null); return; }
        const t = await api.trail(id);
        const mine = sg.filter((s) => s.signed_record_id === id);
        const vs = await Promise.all(mine.map((s) => api.verifySignature(s.id)));
        if (!live) return;
        setTrail(t);
        setChecks(Object.fromEntries(vs.map((v) => [v.signature_id, v])));
      } catch (e) {
        if (live) setError(String(e));
      }
    })();
    return () => { live = false; };
  }, [api, selectedId]);

  if (error) return <main><p className="review">Failed to load: {error}</p></main>;
  if (!api) return <main><p className="muted">Loading…</p></main>;
  const indexOf = new Map(events.map((e, i) => [e.id, i]));
  const mySigs = sigs.filter((s) => s.signed_record_id === selectedId);

  return (
    <main>
      <header>
        <div>
          <h1>part11-audit-trail</h1>
          <p className="muted">
            The Documenter: reads the hash-chained, append-only audit log and reports integrity findings. It never writes, alters or re-orders entries; a broken chain is reported, not repaired.
          </p>
        </div>
        <div className="topbar">
          <span className="badge">{api.mode === "seed" ? "demo mode — seeded data, verified in the browser" : "live — verified by the server"}</span>
          {conn?.tampered ? (
            <label className="toggle">
              <input type="checkbox" checked={tampered} onChange={(e) => setTampered(e.target.checked)} />
              Simulate tampering
              <span className="muted small">(rewrite entry #5's actor, edit SOP-017 after signing)</span>
            </label>
          ) : null}
        </div>
      </header>

      {trail ? <Banner integrity={trail.integrity} events={events} /> : <p className="muted">No audit events yet. PUT a record to /records/{"{type}/{id}"} to start the trail.</p>}

      <div className="layout">
        <RecordList events={events} selected={selectedId} onSelect={setSelectedId} />
        <div>
          {trail ? (
            <>
              <h2>Audit trail · <code>{trail.record_id}</code> <span className="muted small">{trail.events.length} events · row # is the position in the full chain</span></h2>
              <TrailTable trail={trail} indexOf={indexOf} />
              <SignaturesPanel sigs={mySigs} checks={checks} />
            </>
          ) : null}
        </div>
      </div>

      <footer className="muted small">21 CFR Part 11 · ALCOA+ · demo-grade auth (production: MFA per §11.200)</footer>
    </main>
  );
}
