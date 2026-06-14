import { useState } from "react";
import { clearLog } from "../api";
import type { LogEntry } from "../types";
import { prettyTs } from "../util";

interface Props {
  log: LogEntry[];
  // Called after a successful clear so the parent can re-pull /api/state.
  onChanged?: () => void;
}

const MAX_LINES = 200;
const COLLAPSE_KEY = "rv6699.log.collapsed";

function loadCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

// Self-contained Event log card: collapsible header with a count chip and a
// Clear button; newest-first lines, capped so the DOM can't run away.
export default function EventLog({ log, onChanged }: Props) {
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const [busy, setBusy] = useState(false);

  const all = log || [];
  const rows = all.slice().reverse().slice(0, MAX_LINES);
  const hidden = all.length - rows.length;

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
    } catch {
      /* localStorage unavailable — collapse still works in-memory */
    }
  };

  const clear = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await clearLog();
      onChanged?.();
    } catch {
      /* leave lines in place; next poll reflects reality */
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>
        <button
          className="chev"
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expand" : "Collapse"}
          onClick={toggle}
        >
          {collapsed ? "▸" : "▾"}
        </button>
        Event log <span className="chip">{all.length}</span>
        <span className="head-actions">
          <button
            className="danger sm"
            onClick={clear}
            disabled={busy || !all.length}
            title="Clear the event log"
          >
            Clear
          </button>
        </span>
      </h2>
      {!collapsed && (
        <div className="body">
          <div className="log">
            {rows.map((l, i) => (
              <div key={i} className={"l " + (l.level || "info")}>
                <span className="ts">{prettyTs(l.ts)}</span>{" "}
                {l.key ? "[" + l.key + "] " : ""}
                {l.msg}
              </div>
            ))}
            {hidden > 0 && (
              <div className="mut" style={{ marginTop: 6 }}>
                + {hidden} older lines not shown
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
