import { useCallback, useEffect, useRef, useState } from "react";
import { getDevice, getState } from "./api";
import type { AcsState, DeviceDetail } from "./types";
import CapturesBanner from "./components/CapturesBanner";
import DeviceDetailView from "./components/DeviceDetailView";
import DeviceList from "./components/DeviceList";
import EventLog from "./components/EventLog";
import SettingsPanel from "./components/Settings";
import WireViewer from "./components/WireViewer";

const POLL_MS = 2500;

export default function App() {
  const [state, setState] = useState<AcsState | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [filter, setFilter] = useState("");
  const [clock, setClock] = useState(() => new Date().toLocaleTimeString());
  const [showSettings, setShowSettings] = useState(false);
  const [showWire, setShowWire] = useState(false);

  // Keep the latest selection readable from the polling closure.
  const selRef = useRef<string | null>(null);
  selRef.current = selected;

  const refresh = useCallback(async () => {
    try {
      const s = await getState();
      setState(s);
      const key = selRef.current;
      if (key) {
        try {
          setDetail(await getDevice(key));
        } catch {
          /* device may have disappeared; keep last detail */
        }
      }
    } catch {
      /* network blip — keep last state, try again next tick */
    }
  }, []);

  // Poll /api/state (+ selected device) every 2.5s.
  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  // Header clock ticking once a second.
  useEffect(() => {
    const id = window.setInterval(
      () => setClock(new Date().toLocaleTimeString()),
      1000,
    );
    return () => window.clearInterval(id);
  }, []);

  const select = useCallback(async (key: string) => {
    setSelected(key);
    selRef.current = key;
    try {
      setDetail(await getDevice(key));
    } catch {
      setDetail(null);
    }
  }, []);

  const cfg = state?.config;
  const devices = state?.devices || [];
  const log = state?.log || [];
  const captures = state?.captures || [];

  return (
    <>
      <header>
        <h1>rv6699 ACS</h1>
        <span className="meta">
          ACS URL → <span className="acsurl">{cfg?.acs_url || ""}</span>
        </span>
        <span className="meta">
          {"auth: " + (cfg?.auth || "") + " · CR user: " + (cfg?.cr_username || "")}
        </span>
        <span className="meta">{devices.length + " device(s)"}</span>
        <button
          style={{ marginLeft: "auto" }}
          onClick={() => setShowWire(true)}
        >
          🔌 Wire
        </button>
        <button onClick={() => setShowSettings(true)}>⚙ Settings</button>
        <span className="meta">{clock}</span>
      </header>
      {cfg?.needs_setup && (
        <div className="banner-setup">
          ⚠ Using an auto-generated admin password — open{" "}
          <button className="linkish" onClick={() => setShowSettings(true)}>
            Settings
          </button>{" "}
          to set your own (it was printed in the server logs).
        </div>
      )}
      <div className="wrap">
        <DeviceList devices={devices} selected={selected} onSelect={select} />
        <main>
          {selected && detail ? (
            <DeviceDetailView
              device={detail}
              captures={captures}
              log={log}
              filter={filter}
              onFilter={setFilter}
              onChanged={refresh}
            />
          ) : (
            <>
              <CapturesBanner captures={captures} />
              {devices.length || captures.length ? (
                <div className="card">
                  <h2>Event log</h2>
                  <div className="body">
                    <EventLog log={log} />
                  </div>
                </div>
              ) : (
                <div className="empty">
                  Select a device, or point your router's ACS URL here and wait
                  for an Inform.
                </div>
              )}
            </>
          )}
        </main>
      </div>
      {showSettings && (
        <SettingsPanel
          onClose={() => setShowSettings(false)}
          onSaved={refresh}
        />
      )}
      {showWire && <WireViewer onClose={() => setShowWire(false)} />}
    </>
  );
}
