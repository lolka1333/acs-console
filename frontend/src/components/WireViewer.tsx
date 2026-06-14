import { useCallback, useEffect, useRef, useState } from "react";
import { clearWire, getWire } from "../api";
import type { WireEntry } from "../types";
import { prettyTs } from "../util";

interface Props {
  onClose: () => void;
}

const POLL_MS = 1500;

// One captured CWMP frame: a direction badge, timestamp + summary, and a
// collapsible details block with headers and the raw XML body.
function WireRow({ e }: { e: WireEntry }) {
  const inbound = e.dir === "in";
  const arrow = inbound ? "CPE → ACS" : "ACS → CPE";
  const headerLines = Object.entries(e.headers || {});
  return (
    <div className={"wire-row " + (inbound ? "wire-in" : "wire-out")}>
      <div className="wire-head">
        <span className="wire-dir">{arrow}</span>
        <span className="wire-ts">{prettyTs(e.ts)}</span>
        <span className="wire-sum">{e.summary}</span>
        <span className="wire-ip mut">
          {e.client_ip}
          {e.session_key ? " · " + e.session_key : ""}
        </span>
      </div>
      <details>
        <summary>headers + body</summary>
        {headerLines.length > 0 && (
          <pre className="wire-headers">
            {headerLines.map(([k, v]) => k + ": " + v).join("\n")}
          </pre>
        )}
        <pre className="wire-body">{e.body || "(empty)"}</pre>
      </details>
    </div>
  );
}

// Live viewer for the diagnostic CWMP wire log. Polls GET /api/wire while open
// and renders captured frames oldest -> newest. Same dark modal style as
// Settings.tsx.
export default function WireViewer({ onClose }: Props) {
  const [enabled, setEnabled] = useState<boolean>(false);
  const [entries, setEntries] = useState<WireEntry[]>([]);
  const [err, setErr] = useState<string>("");
  const [loaded, setLoaded] = useState(false);
  const aliveRef = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const w = await getWire();
      if (!aliveRef.current) return;
      setEnabled(w.enabled);
      setEntries(w.entries || []);
      setErr("");
      setLoaded(true);
    } catch {
      if (!aliveRef.current) return;
      setErr("Could not load the wire log (are you logged in?).");
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => {
      aliveRef.current = false;
      window.clearInterval(id);
    };
  }, [refresh]);

  const onClear = useCallback(async () => {
    try {
      await clearWire();
    } catch {
      /* ignore — next poll will resync */
    }
    void refresh();
  }, [refresh]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal wire-modal" onClick={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <h2>🔌 Wire log</h2>
          <div className="row" style={{ margin: 0, gap: 8 }}>
            <span className="pill">{entries.length} frame(s)</span>
            <button className="danger" onClick={() => void onClear()}>
              Clear
            </button>
            <button onClick={onClose}>✕ Close</button>
          </div>
        </header>

        <div className="modal-body">
          {err && <div className="set-err">{err}</div>}
          {!enabled && (
            <div className="set-note" style={{ color: "var(--warn)" }}>
              Wire logging is off — enable it in ⚙ Settings.
            </div>
          )}
          {loaded && entries.length === 0 && !err && (
            <div className="mut" style={{ marginTop: 12 }}>
              No CWMP frames captured yet
              {enabled ? " — waiting for the router…" : "."}
            </div>
          )}
          <div className="wire-list">
            {entries.map((e) => (
              <WireRow key={e.id} e={e} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
