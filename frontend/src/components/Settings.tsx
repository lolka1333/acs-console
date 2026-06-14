import { useEffect, useState } from "react";
import { getSettings, putSettings } from "../api";
import type { Settings, SettingsUpdate } from "../types";

interface Props {
  onClose: () => void;
  // Called after a successful save so the parent can refresh /api/state.
  onSaved: () => void;
}

const CHALLENGES: Array<Settings["challenge"]> = ["basic", "digest", "both"];

// A small labelled badge that reflects whether a secret is currently set.
function SetTag({ on }: { on: boolean }) {
  return (
    <span className="tag" style={on ? { color: "var(--ok)", borderColor: "var(--ok)" } : {}}>
      {on ? "set" : "not set"}
    </span>
  );
}

// Full-screen Settings modal. Loads the redacted view from GET /api/settings,
// then PUTs only the fields the operator actually touched.
export default function SettingsPanel({ onClose, onSaved }: Props) {
  const [s, setS] = useState<Settings | null>(null);
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string>("");

  // Form state. Booleans/selects/usernames mirror the loaded view; password
  // fields start blank (we never receive the real secrets) and only become a
  // patch field when the operator types into them.
  const [acsAuthEnabled, setAcsAuthEnabled] = useState(false);
  const [acsUsername, setAcsUsername] = useState("");
  const [acsPassword, setAcsPassword] = useState("");
  const [acsPasswordTouched, setAcsPasswordTouched] = useState(false);

  const [capture, setCapture] = useState(false);
  const [challenge, setChallenge] = useState<Settings["challenge"]>("basic");

  const [consoleUsername, setConsoleUsername] = useState("");
  const [consolePassword, setConsolePassword] = useState("");
  const [consolePassword2, setConsolePassword2] = useState("");
  const [clearConsolePassword, setClearConsolePassword] = useState(false);

  const [crUsername, setCrUsername] = useState("");
  const [crPassword, setCrPassword] = useState("");
  const [crPasswordTouched, setCrPasswordTouched] = useState(false);

  const [advertiseHost, setAdvertiseHost] = useState("");

  const [debugWire, setDebugWire] = useState(false);

  function hydrate(v: Settings) {
    setS(v);
    setAcsAuthEnabled(v.acs_auth_enabled);
    setAcsUsername(v.acs_username);
    setAcsPassword("");
    setAcsPasswordTouched(false);
    setCapture(v.capture);
    setChallenge(v.challenge);
    setConsoleUsername(v.console_username);
    setConsolePassword("");
    setConsolePassword2("");
    setClearConsolePassword(false);
    setCrUsername(v.cr_username);
    setCrPassword("");
    setCrPasswordTouched(false);
    setAdvertiseHost(v.advertise_host);
    setDebugWire(v.debug_wire);
  }

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const v = await getSettings();
        if (alive) hydrate(v);
      } catch {
        if (alive) setErr("Could not load settings (are you logged in?).");
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function save() {
    if (!s) return;
    setErr("");
    setNote("");

    const patch: SettingsUpdate = {};

    // --- ACS (CPE) authentication ---
    if (!acsAuthEnabled) {
      // Turning auth off clears the ACS password regardless of what's typed.
      if (s.acs_auth_enabled) patch.acs_password = "";
    } else {
      if (acsUsername !== s.acs_username) patch.acs_username = acsUsername;
      if (acsPasswordTouched) patch.acs_password = acsPassword;
      // Enabling auth with no stored secret and no typed one is meaningless.
      if (!s.acs_auth_enabled && !acsPasswordTouched) {
        setErr("Set an ACS password to require the router to authenticate.");
        return;
      }
    }

    // --- Capture mode ---
    if (capture !== s.capture) patch.capture = capture;
    if (challenge !== s.challenge) patch.challenge = challenge;

    // --- Console login ---
    if (consoleUsername !== s.console_username) patch.console_username = consoleUsername;
    let consoleChanged = false;
    if (clearConsolePassword) {
      patch.console_password = "";
      consoleChanged = true;
    } else if (consolePassword.length > 0) {
      if (consolePassword !== consolePassword2) {
        setErr("Console passwords do not match.");
        return;
      }
      patch.console_password = consolePassword;
      consoleChanged = true;
    }

    // --- Connection Request ---
    if (crUsername !== s.cr_username) patch.cr_username = crUsername;
    if (crPasswordTouched) patch.cr_password = crPassword;

    // --- Advertise host ---
    if (advertiseHost !== s.advertise_host) patch.advertise_host = advertiseHost;

    // --- Diagnostics ---
    if (debugWire !== s.debug_wire) patch.debug_wire = debugWire;

    if (Object.keys(patch).length === 0) {
      setNote("No changes to save.");
      return;
    }

    setBusy(true);
    try {
      const v = await putSettings(patch);
      hydrate(v);
      onSaved();
      if (consoleChanged) {
        setNote(
          clearConsolePassword
            ? "Saved. The console is now open (no login required)."
            : "Saved. The console password changed — your browser will ask you to log in again.",
        );
      } else {
        setNote("Saved.");
      }
    } catch {
      setErr("Save failed. Check the server logs.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <h2>⚙ Settings</h2>
          <button onClick={onClose}>✕ Close</button>
        </header>

        <div className="modal-body">
          {!s ? (
            <div className="mut">{err || "Loading…"}</div>
          ) : (
            <>
              {/* ACS authentication */}
              <section className="set-sec">
                <h3>Router authentication (ACS)</h3>
                <label className="set-check">
                  <input
                    type="checkbox"
                    checked={acsAuthEnabled}
                    onChange={(e) => setAcsAuthEnabled(e.target.checked)}
                  />
                  Require the router to authenticate
                </label>
                {acsAuthEnabled && (
                  <div className="set-grid">
                    <label>ACS username</label>
                    <input
                      value={acsUsername}
                      onChange={(e) => setAcsUsername(e.target.value)}
                      placeholder="username the router must send"
                    />
                    <label>
                      ACS password <SetTag on={s.acs_auth_enabled} />
                    </label>
                    <input
                      type="password"
                      value={acsPassword}
                      onChange={(e) => {
                        setAcsPassword(e.target.value);
                        setAcsPasswordTouched(true);
                      }}
                      placeholder={s.acs_auth_enabled ? "(unchanged)" : "set a password"}
                    />
                  </div>
                )}
                {!acsAuthEnabled && (
                  <div className="mut set-hint">
                    Off = the ACS accepts Informs without checking credentials.
                  </div>
                )}
              </section>

              {/* Capture mode */}
              <section className="set-sec">
                <h3>Credential capture</h3>
                <label className="set-check">
                  <input
                    type="checkbox"
                    checked={capture}
                    onChange={(e) => setCapture(e.target.checked)}
                  />
                  Capture mode (challenge the router and record what it sends)
                </label>
                <div className="set-grid">
                  <label>Challenge scheme</label>
                  <select
                    value={challenge}
                    onChange={(e) => setChallenge(e.target.value as Settings["challenge"])}
                  >
                    {CHALLENGES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
              </section>

              {/* Console login */}
              <section className="set-sec">
                <h3>Console login</h3>
                <div className="set-grid">
                  <label>Console username</label>
                  <input
                    value={consoleUsername}
                    onChange={(e) => setConsoleUsername(e.target.value)}
                  />
                  <label>
                    New password{" "}
                    <SetTag on={s.console_password_set} />
                    {s.console_password_generated && (
                      <span className="tag" style={{ color: "var(--warn)", borderColor: "var(--warn)" }}>
                        auto-generated
                      </span>
                    )}
                  </label>
                  <input
                    type="password"
                    value={consolePassword}
                    disabled={clearConsolePassword}
                    onChange={(e) => setConsolePassword(e.target.value)}
                    placeholder={s.console_password_set ? "(unchanged)" : "set a password"}
                  />
                  <label>Confirm password</label>
                  <input
                    type="password"
                    value={consolePassword2}
                    disabled={clearConsolePassword}
                    onChange={(e) => setConsolePassword2(e.target.value)}
                    placeholder="repeat new password"
                  />
                </div>
                <label className="set-check">
                  <input
                    type="checkbox"
                    checked={clearConsolePassword}
                    onChange={(e) => setClearConsolePassword(e.target.checked)}
                  />
                  Open the console (no login required)
                </label>
              </section>

              {/* Connection Request */}
              <section className="set-sec">
                <h3>Connection Request credentials</h3>
                <div className="set-grid">
                  <label>CR username</label>
                  <input value={crUsername} onChange={(e) => setCrUsername(e.target.value)} />
                  <label>
                    CR password <SetTag on={s.cr_password_set} />
                  </label>
                  <input
                    type="password"
                    value={crPassword}
                    onChange={(e) => {
                      setCrPassword(e.target.value);
                      setCrPasswordTouched(true);
                    }}
                    placeholder={s.cr_password_set ? "(unchanged)" : "set a password"}
                  />
                </div>
              </section>

              {/* Advertise host */}
              <section className="set-sec">
                <h3>Advertise host</h3>
                <div className="set-grid">
                  <label>Host / domain</label>
                  <input
                    className="wide"
                    value={advertiseHost}
                    onChange={(e) => setAdvertiseHost(e.target.value)}
                    placeholder="auto (from your domain)"
                  />
                </div>
                <div className="mut set-hint">
                  Leave blank for automatic — the ACS uses the host the router reached it on.
                  Currently:{" "}
                  <span className="acsurl">
                    {s.advertise_effective || "(not learned yet)"}
                  </span>
                </div>
              </section>

              {/* Diagnostics */}
              <section className="set-sec">
                <h3>Diagnostics</h3>
                <label className="set-check">
                  <input
                    type="checkbox"
                    checked={debugWire}
                    onChange={(e) => setDebugWire(e.target.checked)}
                  />
                  Debug wire log (capture raw CWMP frames)
                </label>
                <div className="mut set-hint">
                  logs every CWMP request/response to data/wire.log and the 🔌 Wire
                  viewer (credentials are masked)
                </div>
              </section>

              {err && <div className="set-err">{err}</div>}
              {note && <div className="set-note">{note}</div>}
            </>
          )}
        </div>

        <footer className="modal-foot">
          <button onClick={onClose}>Cancel</button>
          <button className="acc" disabled={!s || busy} onClick={() => void save()}>
            {busy ? "Saving…" : "Save settings"}
          </button>
        </footer>
      </div>
    </div>
  );
}
