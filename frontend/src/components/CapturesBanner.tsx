import { useState } from "react";
import { clearCaptures } from "../api";
import type { Capture } from "../types";
import { prettyTs } from "../util";

interface Props {
  captures: Capture[];
  // Called after a successful clear so the parent can re-pull /api/state.
  onChanged?: () => void;
}

const MAX_ROWS = 50;
const COLLAPSE_KEY = "rv6699.captures.collapsed";

// Persist the collapse preference so it survives reloads/polls.
function loadCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

// The secret/value a row exposes: plaintext password (Basic) or the digest hash.
function rowSecret(c: Capture): string {
  return (c.scheme === "basic" ? c.password : c.response) || "";
}

// The prominent 🔑 Captured ACS credentials banner. Rows are DEDUPED — one per
// unique credential — with a seen×count·first→last column, a copy button, a
// header Clear button, and a collapsible body (state remembered).
export default function CapturesBanner({ captures, onChanged }: Props) {
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const [copied, setCopied] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  if (!captures.length) return null;

  // Newest unique credential first, capped so a noisy CPE can't blow up the DOM.
  const rows = captures.slice().reverse().slice(0, MAX_ROWS);
  const hidden = captures.length - rows.length;

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
    } catch {
      /* localStorage unavailable (private mode) — collapse still works in-memory */
    }
  };

  const copy = async (c: Capture, i: number) => {
    const secret = rowSecret(c);
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(i);
      window.setTimeout(() => setCopied((v) => (v === i ? null : v)), 1200);
    } catch {
      /* clipboard blocked (insecure context) — silently ignore */
    }
  };

  const clear = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await clearCaptures();
      onChanged?.();
    } catch {
      /* leave rows in place; next poll reflects reality */
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ borderColor: "var(--warn)" }}>
      <h2 style={{ color: "var(--warn)" }}>
        <button
          className="chev"
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expand" : "Collapse"}
          onClick={toggle}
        >
          {collapsed ? "▸" : "▾"}
        </button>
        🔑 Captured ACS credentials{" "}
        <span className="chip">{captures.length} unique</span>
        <span className="head-actions">
          <button
            className="danger sm"
            onClick={clear}
            disabled={busy}
            title="Clear all captured credentials"
          >
            Clear
          </button>
        </span>
      </h2>
      {!collapsed && (
        <div className="body">
          <table className="dense">
            <thead>
              <tr>
                <th>Scheme</th>
                <th>Username</th>
                <th>Password / hash</th>
                <th>Seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c, i) => {
                const secret = rowSecret(c);
                return (
                  <tr key={c.scheme + ":" + c.username + ":" + secret + ":" + i}>
                    <td>{c.scheme}</td>
                    <td className="val">{c.username || ""}</td>
                    <td className="val">
                      {c.scheme === "basic" ? (
                        <b style={{ color: "var(--ok)" }}>{c.password}</b>
                      ) : (
                        <>
                          <span className="hash">{c.response || ""}</span>{" "}
                          <span className="mut">
                            (Digest — crack with crack_acs_digest.py)
                          </span>
                        </>
                      )}
                    </td>
                    <td className="mut seen" title={prettyTs(c.first) + " → " + prettyTs(c.last)}>
                      ×{c.count} · {prettyTs(c.first)}
                      {c.last !== c.first ? " → " + prettyTs(c.last) : ""}
                    </td>
                    <td>
                      <button
                        className="sm"
                        onClick={() => void copy(c, i)}
                        disabled={!secret}
                        title="Copy password / hash"
                      >
                        {copied === i ? "✓" : "copy"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {hidden > 0 && (
            <div className="mut" style={{ marginTop: 6 }}>
              + {hidden} more not shown
            </div>
          )}
        </div>
      )}
    </div>
  );
}
