import type { DeviceDetail } from "../types";
import { postConnReq, postDiscover, postTask } from "../api";

interface Props {
  device: DeviceDetail;
  // Called after any mutating action so the parent can refresh shortly after.
  onChanged: () => void;
}

const isUrl = (s: string) => /^[a-z]+:\/\//i.test(s);

export default function Actions({ device: d, onChanged }: Props) {
  const key = d.key;
  const root = d.root || "InternetGatewayDevice.";

  // Enqueue a task, then schedule a refresh (mirrors index.html's setTimeout 300).
  async function task(type: string, args: Record<string, unknown>, label: string) {
    await postTask(key, type, args, label);
    setTimeout(onChanged, 300);
  }

  async function discover() {
    const path = window.prompt("Discover from path:", root);
    if (path == null) return;
    await postDiscover(key, { path });
    setTimeout(onChanged, 300);
  }

  async function connreq() {
    const r = await postConnReq(key);
    window.alert((r.ok ? "OK: " : "FAILED: ") + r.detail);
  }

  function getParams() {
    const raw = window.prompt(
      "Parameter name(s), comma-separated (a trailing '.' fetches a whole subtree):",
      root + "DeviceInfo.",
    );
    if (!raw) return;
    void task(
      "get",
      { names: raw.split(",").map((s) => s.trim()).filter(Boolean) },
      "get " + raw,
    );
  }

  function setParam() {
    const name = window.prompt(
      "Parameter name:",
      root + "ManagementServer.PeriodicInformInterval",
    );
    if (!name) return;
    const value = window.prompt("New value:");
    if (value == null) return;
    void task(
      "set",
      { params: [[name, value, ""]], parameter_key: "acs-" + Date.now() },
      "set " + name,
    );
  }

  function quickInfo() {
    void task(
      "get",
      { names: [root + "DeviceInfo.", root + "ManagementServer."] },
      "get DeviceInfo+MgmtServer",
    );
  }

  function quickWifi() {
    void task(
      "get",
      { names: [root + "LANDevice.1.WLANConfiguration."] },
      "get WLAN subtree",
    );
  }

  function quickHosts() {
    void task("get", { names: [root + "LANDevice.1.Hosts."] }, "get Hosts subtree");
  }

  function getRpc() {
    void task("getrpcmethods", {}, "GetRPCMethods");
  }

  function addObj() {
    const o = window.prompt("Object table to add a row to (trailing '.'):");
    if (o)
      void task(
        "addobject",
        { object_name: o, parameter_key: "acs-" + Date.now() },
        "AddObject " + o,
      );
  }

  function delObj() {
    const o = window.prompt("Object instance to delete (e.g. ...IPInterface.3.):");
    if (o)
      void task(
        "deleteobject",
        { object_name: o, parameter_key: "acs-" + Date.now() },
        "DeleteObject " + o,
      );
  }

  function download() {
    const url = window.prompt(
      "Firmware/file URL the CPE should download (or put a file in files/ and enter just its name):",
    );
    if (!url) return;
    const ft = window.prompt("FileType:", "1 Firmware Upgrade Image");
    const isName = !isUrl(url);
    void task(
      "download",
      isName
        ? { file: url, file_type: ft, command_key: "dl-" + Date.now() }
        : { url, file_type: ft, command_key: "dl-" + Date.now() },
      "Download " + url,
    );
  }

  function upload() {
    const ft = window.prompt("Upload FileType:", "1 Vendor Configuration File");
    if (ft == null) return;
    const name = window.prompt("Save uploaded file as:", "cpe-config.bin");
    if (!name) return;
    void task(
      "upload",
      { file: name, file_type: ft, command_key: "ul-" + Date.now() },
      "Upload " + name,
    );
  }

  function reboot() {
    if (window.confirm("Reboot the router now?"))
      void task("reboot", { command_key: "acs-reboot" }, "REBOOT");
  }

  function factory() {
    if (
      window.confirm(
        "FACTORY RESET? This wipes config incl. your ACS URL and returns the box to MGTS defaults. Are you sure?",
      ) &&
      window.confirm("Really factory reset?")
    )
      void task("factoryreset", {}, "FACTORY RESET");
  }

  return (
    <div className="card">
      <h2>
        Actions <span className="pill">{(d.queue || []).length} queued</span>
      </h2>
      <div className="body">
        <div className="grp">
          <button className="acc" onClick={discover}>
            🔍 Discover data model
          </button>
          <button onClick={quickInfo}>Device info</button>
          <button onClick={quickWifi}>Wi-Fi (SSID/keys)</button>
          <button onClick={quickHosts}>Connected hosts</button>
          <button onClick={getRpc}>GetRPCMethods</button>
          <button onClick={connreq}>📡 Connection Request</button>
        </div>
        <div className="grp">
          <button onClick={getParams}>GetParameterValues…</button>
          <button onClick={setParam}>SetParameterValues…</button>
          <button onClick={addObj}>AddObject…</button>
          <button onClick={delObj}>DeleteObject…</button>
          <button onClick={download}>Download…</button>
          <button onClick={upload}>Upload…</button>
        </div>
        <div className="grp">
          <button className="danger" onClick={reboot}>
            Reboot
          </button>
          <button className="danger" onClick={factory}>
            Factory reset
          </button>
        </div>
      </div>
    </div>
  );
}
