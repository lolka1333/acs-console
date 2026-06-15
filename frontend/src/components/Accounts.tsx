import { useEffect, useMemo, useState } from "react";
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

  // Server truth, parsed straight from the fetched data model.
  const { accounts, shell, serverVals, hasData } = useMemo(() => {
    const byInst: Record<string, Account> = {};
    const serverVals: Record<string, string> = {};
    let shell: Field | null = null;
    for (const p of d.parameters || []) {
      if (p.name === shellName) {
        shell = { value: p.value, writable: p.writable };
        serverVals[p.name] = p.value;
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
      serverVals[p.name] = p.value;
    }
    const accounts = Object.values(byInst).sort((a, b) => +a.inst - +b.inst);
    return { accounts, shell, serverVals, hasData: accounts.length > 0 || shell != null };
  }, [d.parameters, acctBase, shellName]);

  // Optimistic overrides keyed by full parameter name: a click shows instantly
  // (a queued Set only reaches the CPE on its next contact), and each override
  // is dropped once a later read-back confirms the same value on the server.
  const [pending, setPending] = useState<Record<string, string>>({});
  useEffect(() => setPending({}), [d.key]); // forget overrides when switching device
  useEffect(() => {
    setPending((prev) => {
      let next = prev;
      for (const name in prev) {
        if (serverVals[name] === prev[name]) {
          if (next === prev) next = { ...prev };
          delete next[name];
        }
      }
      return next;
    });
  }, [serverVals]);

  const effective = (name: string, server?: string) =>
    name in pending ? pending[name] : server;

  async function task(type: string, args: Record<string, unknown>, label: string) {
    await postTask(d.key, type, args, label);
    setTimeout(onChanged, 300);
  }

  const subtree = () => ({ names: [acctBase, shellName] });

  function load() {
    void task("get", subtree(), "get LoginAccount + ShellEnable");
  }

  // Queue one SetParameterValues for one or more params and update the optimistic
  // view synchronously. Confirmed values arrive via the parent poll / Load / Apply.
  function setFields(params: [string, string, string][], label: string) {
    setPending((p) => {
      const next = { ...p };
      for (const [name, value] of params) next[name] = value;
      return next;
    });
    void task("set", { params, parameter_key: "acs-" + Date.now() }, label);
  }
  const setField = (name: string, value: string, label: string) =>
    setFields([[name, value, ""]], label);

  function setGroup(a: Account, g: string) {
    setField(`${acctBase}${a.inst}.Group`, g, `account ${a.inst}: Group=${g}`);
  }

  function togglePerm(a: Account, tok: string) {
    const name = `${acctBase}${a.inst}.Permission`;
    const cur = permSet(effective(name, a.fields.Permission?.value));
    if (cur.has(tok)) cur.delete(tok);
    else cur.add(tok);
    const ordered = PERMS.filter((t) => cur.has(t)).concat(
      [...cur].filter((t) => !PERMS.includes(t)),
    );
    setField(
      name,
      ordered.join(","),
      `account ${a.inst}: Permission=${ordered.join(",") || "(none)"}`,
    );
  }

  function toggleEnable(a: Account) {
    const name = `${acctBase}${a.inst}.Enable`;
    const on = isOn(effective(name, a.fields.Enable?.value));
    setField(name, on ? "0" : "1", `account ${a.inst}: ${on ? "disable" : "enable"}`);
  }

  function setShell(on: boolean) {
    setField(shellName, on ? "1" : "0", `ShellEnable=${on ? 1 : 0}`);
  }

  // The common workflow: promote to admin AND open the shell gate, in one
  // atomic SetParameterValues (TR-069 SPV carries multiple params natively).
  function makeAdmin(a: Account) {
    setFields(
      [[`${acctBase}${a.inst}.Group`, "admin", ""], [shellName, "1", ""]],
      `account ${a.inst}: -> admin + ShellEnable=1`,
    );
  }

  // Push queued changes now: queue a read-back first so the CPE drains the
  // pending Sets and then this Get within one session, then open the session.
  async function applyNow() {
    await postTask(d.key, "get", subtree(), "refresh accounts");
    const r = await postConnReq(d.key);
    setTimeout(onChanged, 300);
    window.alert((r.ok ? "OK: " : "FAILED: ") + r.detail);
  }

  function reboot() {
    if (window.confirm("Reboot the router now to apply group / permission changes?"))
      void task("reboot", { command_key: "acs-reboot" }, "REBOOT");
  }

  const acctLabel = (a: Account) =>
    a.fields.UserName?.value || a.fields.FullName?.value || "(account " + a.inst + ")";

  const shellKnown = shell != null || shellName in pending;
  const shellOn = isOn(effective(shellName, shell?.value));

  return (
    <div className="card">
      <h2>
        Users &amp; Groups <span className="pill">{accounts.length} account(s)</span>
        <span className="head-actions">
          <button type="button" className="sm" onClick={load}>
            ↻ Load
          </button>
          <button
            type="button"
            className="sm"
            onClick={applyNow}
            title="Connection Request — push the queued changes now"
          >
            📡 Apply now
          </button>
        </span>
      </h2>
      <div className="body">
        <div className="row">
          <span className="mut">Shell access (X_SC_Management.ShellEnable):</span>
          <span className={"chip" + (shellKnown && shellOn ? " on" : "")}>
            {shellKnown ? (shellOn ? "ON" : "OFF") : "unknown"}
          </span>
          <button type="button" className="sm" onClick={() => setShell(true)}>
            Enable shell
          </button>
          <button type="button" className="sm" onClick={() => setShell(false)}>
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
                  const group = effective(`${acctBase}${a.inst}.Group`, a.fields.Group?.value);
                  const perms = permSet(
                    effective(`${acctBase}${a.inst}.Permission`, a.fields.Permission?.value),
                  );
                  const enabled = isOn(
                    effective(`${acctBase}${a.inst}.Enable`, a.fields.Enable?.value),
                  );
                  return (
                    <tr key={a.inst}>
                      <td className="mut">{a.inst}</td>
                      <td className="val">{acctLabel(a)}</td>
                      <td>
                        <div className="grp">
                          {GROUPS.map((g) => (
                            <button
                              key={g}
                              type="button"
                              className={"sm" + (group === g ? " acc" : "")}
                              aria-pressed={group === g}
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
                            <button
                              key={tok}
                              type="button"
                              className={"chip" + (perms.has(tok) ? " on" : "")}
                              aria-pressed={perms.has(tok)}
                              onClick={() => togglePerm(a, tok)}
                            >
                              {tok}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="sm"
                          aria-pressed={enabled}
                          onClick={() => toggleEnable(a)}
                        >
                          {enabled ? "✓ on" : "✗ off"}
                        </button>
                      </td>
                      <td>
                        <button
                          type="button"
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
          <code>sh</code> becomes visible.{" "}
          <button type="button" className="sm" onClick={reboot}>
            Reboot to apply
          </button>
        </div>
      </div>
    </div>
  );
}
