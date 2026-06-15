import { useMemo } from "react";
import type { DeviceDetail } from "../types";
import { postConnReq, postTask } from "../api";

interface Props {
  device: DeviceDetail;
  // Called after any mutating action so the parent can refresh shortly after.
  onChanged: () => void;
}

interface Field {
  value: string;
  writable: string;
}
interface Account {
  inst: string;
  fields: Record<string, Field>;
}

// RV6699 (Sercomm) management groups and the permission tokens its CLI uses.
const GROUPS = ["admin", "support", "user"];
const PERMS = ["web", "cli", "ftp", "smb"];

const isOn = (v?: string) => v === "1" || /^true$/i.test(v ?? "");
const permSet = (v?: string) =>
  new Set((v ?? "").split(",").map((s) => s.trim()).filter(Boolean));

export default function Accounts({ device: d, onChanged }: Props) {
  const root = d.root || "InternetGatewayDevice.";
  const mgmt = root + "X_SC_Management.";
  const acctBase = mgmt + "LoginAccount.";
  const shellName = mgmt + "ShellEnable";

  // Build the account table straight from the already-fetched data model.
  const { accounts, shell, hasData } = useMemo(() => {
    const byInst: Record<string, Account> = {};
    let shell: Field | null = null;
    for (const p of d.parameters || []) {
      if (p.name === shellName) {
        shell = { value: p.value, writable: p.writable };
        continue;
      }
      if (!p.name.startsWith(acctBase)) continue;
      const rest = p.name.slice(acctBase.length); // e.g. "2.Group"
      const dot = rest.indexOf(".");
      if (dot <= 0) continue;
      const inst = rest.slice(0, dot);
      const field = rest.slice(dot + 1);
      if (!/^\d+$/.test(inst) || !field || field.includes(".")) continue;
      let acc = byInst[inst];
      if (!acc) {
        acc = { inst, fields: {} };
        byInst[inst] = acc;
      }
      acc.fields[field] = { value: p.value, writable: p.writable };
    }
    const accounts = Object.values(byInst).sort((a, b) => +a.inst - +b.inst);
    return { accounts, shell, hasData: accounts.length > 0 || shell != null };
  }, [d.parameters, acctBase, shellName]);

  async function task(type: string, args: Record<string, unknown>, label: string) {
    await postTask(d.key, type, args, label);
    setTimeout(onChanged, 300);
  }

  const fetchAll = () => ({ names: [acctBase, shellName] });

  function load() {
    void task("get", fetchAll(), "get LoginAccount + ShellEnable");
  }

  // Queue a Set, then re-read the subtree so the table reflects the new value
  // once the CPE has processed the queue.
  function setField(name: string, value: string, label: string) {
    void task(
      "set",
      { params: [[name, value, ""]], parameter_key: "acs-" + Date.now() },
      label,
    );
    setTimeout(() => void task("get", fetchAll(), "refresh accounts"), 1500);
  }

  function setGroup(a: Account, g: string) {
    setField(`${acctBase}${a.inst}.Group`, g, `account ${a.inst}: Group=${g}`);
  }

  function togglePerm(a: Account, tok: string) {
    const cur = permSet(a.fields.Permission?.value);
    if (cur.has(tok)) cur.delete(tok);
    else cur.add(tok);
    const ordered = PERMS.filter((t) => cur.has(t)).concat(
      [...cur].filter((t) => !PERMS.includes(t)),
    );
    setField(
      `${acctBase}${a.inst}.Permission`,
      ordered.join(","),
      `account ${a.inst}: Permission=${ordered.join(",") || "(none)"}`,
    );
  }

  function toggleEnable(a: Account) {
    const on = isOn(a.fields.Enable?.value);
    setField(
      `${acctBase}${a.inst}.Enable`,
      on ? "0" : "1",
      `account ${a.inst}: ${on ? "disable" : "enable"}`,
    );
  }

  function setShell(on: boolean) {
    setField(shellName, on ? "1" : "0", `ShellEnable=${on ? 1 : 0}`);
  }

  // The common workflow: promote an account to admin AND open the shell gate.
  function makeAdmin(a: Account) {
    setField(`${acctBase}${a.inst}.Group`, "admin", `account ${a.inst}: -> admin`);
    setField(shellName, "1", "ShellEnable=1");
  }

  async function applyNow() {
    const r = await postConnReq(d.key);
    window.alert((r.ok ? "OK: " : "FAILED: ") + r.detail);
  }

  function reboot() {
    if (window.confirm("Reboot the router now to apply group / permission changes?"))
      void task("reboot", { command_key: "acs-reboot" }, "REBOOT");
  }

  const name = (a: Account) =>
    a.fields.UserName?.value || a.fields.FullName?.value || "(account " + a.inst + ")";

  return (
    <div className="card">
      <h2>
        Users &amp; Groups <span className="pill">{accounts.length} account(s)</span>
        <span className="head-actions">
          <button className="sm" onClick={load}>
            ↻ Load
          </button>
          <button className="sm" onClick={applyNow} title="Connection Request — push the queued changes now">
            📡 Apply now
          </button>
        </span>
      </h2>
      <div className="body">
        <div className="row">
          <span className="mut">Shell access (X_SC_Management.ShellEnable):</span>
          <span className={"chip" + (shell && isOn(shell.value) ? " on" : "")}>
            {shell ? (isOn(shell.value) ? "ON" : "OFF") : "unknown"}
          </span>
          <button className="sm" onClick={() => setShell(true)}>
            Enable shell
          </button>
          <button className="sm" onClick={() => setShell(false)}>
            Disable
          </button>
        </div>

        {!hasData ? (
          <div className="mut">
            No account data loaded yet — click <b>↻ Load</b> to fetch the
            LoginAccount table from the device.
          </div>
        ) : (
          <div className="scroll">
            <table className="dense">
              <thead>
                <tr>
                  <th>#</th>
                  <th>User</th>
                  <th>Group</th>
                  <th>Permission</th>
                  <th>Enabled</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => {
                  const group = a.fields.Group?.value;
                  const perms = permSet(a.fields.Permission?.value);
                  return (
                    <tr key={a.inst}>
                      <td className="mut">{a.inst}</td>
                      <td className="val">{name(a)}</td>
                      <td>
                        <div className="grp">
                          {GROUPS.map((g) => (
                            <button
                              key={g}
                              className={"sm" + (group === g ? " acc" : "")}
                              onClick={() => setGroup(a, g)}
                            >
                              {g}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td>
                        <div className="grp">
                          {PERMS.map((tok) => (
                            <span
                              key={tok}
                              className={"chip click" + (perms.has(tok) ? " on" : "")}
                              onClick={() => togglePerm(a, tok)}
                            >
                              {tok}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <button className="sm" onClick={() => toggleEnable(a)}>
                          {isOn(a.fields.Enable?.value) ? "✓ on" : "✗ off"}
                        </button>
                      </td>
                      <td>
                        <button
                          className="sm acc"
                          title="Set Group=admin and ShellEnable=1 (then reboot)"
                          onClick={() => makeAdmin(a)}
                        >
                          ⬆ admin+shell
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="set-hint mut">
          Changes are queued and apply when the CPE next processes the queue (use
          <b> 📡 Apply now</b> to push immediately). Group / permission changes
          need a <b>reboot</b> to regenerate the CLI privilege file before{" "}
          <code>sh</code> becomes visible.
          <button className="sm" style={{ marginLeft: 8 }} onClick={reboot}>
            Reboot to apply
          </button>
        </div>
      </div>
    </div>
  );
}
