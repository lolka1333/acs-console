import type { Capture } from "../types";
import { prettyTs } from "../util";

interface Props {
  captures: Capture[];
}

// The prominent 🔑 Captured ACS credentials banner. Plaintext (Basic) passwords
// are shown in green; Digest captures are noted as crackable.
export default function CapturesBanner({ captures }: Props) {
  if (!captures.length) return null;
  const rows = captures.slice().reverse().slice(0, 20);
  return (
    <div className="card" style={{ borderColor: "var(--warn)" }}>
      <h2 style={{ color: "var(--warn)" }}>
        🔑 Captured ACS credentials <span className="pill">{captures.length}</span>
      </h2>
      <div className="body">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Scheme</th>
              <th>Username</th>
              <th>Password / hash</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c, i) => (
              <tr key={c.ts + ":" + c.key + ":" + i}>
                <td className="mut">{prettyTs(c.ts)}</td>
                <td>{c.scheme}</td>
                <td className="val">{c.username || ""}</td>
                <td className="val">
                  {c.scheme === "basic" ? (
                    <b style={{ color: "var(--ok)" }}>{c.password}</b>
                  ) : (
                    <>
                      {(c.response || "") + " "}
                      <span className="mut">
                        (Digest — crack with crack_acs_digest.py)
                      </span>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
