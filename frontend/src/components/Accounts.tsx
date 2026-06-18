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

// A reasonably strong, unambiguous password (no l/I/O/0).
function genPassword(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const a = new Uint32Array(14);
  crypto.getRandomValues(a);
  return Array.from(a, (x) => chars[x % chars.length]).join("");
}

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

  // Optimistic overrides keyed by full parameter name (instant feedback; cleared
  // once a read-back confirms the same value), plus assorted UI state.
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

  const [dirty, setDirty] = useState(false); // a change is queued but not yet rebooted-in
  const [openMenu, setOpenMenu] = useState<string | null>(null); // open per-row action menu
  const [showCreate, setShowCreate] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");
  const [newGroup, setNewGroup] = useState("admin");
  const [newPerm, setNewPerm] = useState<Set<string>>(() => new Set(["web", "cli"]));

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
    setDirty(true);
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

  function setShell(on: boolean) {
    setField(shellName, on ? "1" : "0", `ShellEnable=${on ? 1 : 0}`);
  }

  // Promote to admin AND open the shell gate, in one atomic SetParameterValues.
  function makeAdmin(a: Account) {
    setFields(
      [[`${acctBase}${a.inst}.Group`, "admin", ""], [shellName, "1", ""]],
      `account ${a.inst}: -> admin + ShellEnable=1`,
    );
  }

  function changePassword(a: Account) {
    const p = window.prompt(`New password for "${acctLabel(a)}":`);
    if (!p) return;
    setField(`${acctBase}${a.inst}.Password`, p, `account ${a.inst}: change password`);
  }

  function rename(a: Account) {
    const v = window.prompt(`Full name for "${acctLabel(a)}":`, a.fields.FullName?.value || "");
    if (v == null) return;
    setField(`${acctBase}${a.inst}.FullName`, v, `account ${a.inst}: rename`);
  }

  function delAccount(a: Account) {
    if (!window.confirm(`Delete account "${acctLabel(a)}" (instance ${a.inst})? This cannot be undone.`))
      return;
    setDirty(true);
    void task(
      "deleteobject",
      { object_name: `${acctBase}${a.inst}.`, parameter_key: "acs-" + Date.now() },
      `delete account ${a.inst}`,
    );
    setTimeout(() => void task("get", subtree(), "refresh accounts"), 1500);
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
    if (window.confirm("Reboot the router now to apply the queued changes?")) {
      void task("reboot", { command_key: "acs-reboot" }, "REBOOT");
      setDirty(false);
    }
  }

  function toggleNewPerm(tok: string) {
    setNewPerm((s) => {
      const n = new Set(s);
      if (n.has(tok)) n.delete(tok);
      else n.add(tok);
      return n;
    });
  }

  // Quick create: one AddObject carrying a `then_set` list; the ACS fills the new
  // instance's fields once the CPE returns its number (see handle_rpc_response).
  async function createAccount() {
    const user = newUser.trim();
    if (!user || !newPass) {
      window.alert("username and password are required");
      return;
    }
    const perm = PERMS.filter((t) => newPerm.has(t)).join(",") || "web,cli";
    await postTask(
      d.key,
      "addobject",
      {
        object_name: acctBase,
        parameter_key: "acs-" + Date.now(),
        then_set: [
          ["UserName", user],
          ["Password", newPass],
          ["Group", newGroup],
          ["Permission", perm],
          ["FullName", user],
        ],
      },
      `create account ${user} (${newGroup})`,
    );
    const r = await postConnReq(d.key);
    setNewUser("");
    setNewPass("");
    setShowCreate(false);
    setDirty(true);
    setTimeout(onChanged, 600);
    window.alert(
      (r.ok ? "Queued + pushed. " : "Queued (push failed: " + r.detail + "). ") +
        "Reboot to apply, then log in as the new user.",
    );
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
          <button type="button" className="sm acc" onClick={() => setShowCreate((v) => !v)}>
            ＋ New
          </button>
        </span>
      </h2>
      <div className="body">
        {dirty && (
          <div className="acct-reboot">
            <span>
              ⚠ Changes are queued. A <b>reboot</b> regenerates the CLI privilege
              file so group / account changes take effect.
            </span>
            <button type="button" className="sm" onClick={reboot}>
              Reboot to apply
            </button>
          </div>
        )}

        <div className="row">
          <span className="mut">Shell access (X_SC_Management.ShellEnable):</span>
          <span className="acct-sw">
            <button
              type="button"
              className={shellKnown && shellOn ? "on" : ""}
              onClick={() => setShell(true)}
            >
              ON
            </button>
            <button
              type="button"
              className={shellKnown && !shellOn ? "off" : ""}
              onClick={() => setShell(false)}
            >
              OFF
            </button>
          </span>
          {!shellKnown && <span className="mut">unknown</span>}
        </div>

        {!hasData ? (
          <div className="mut">
            No account data loaded yet — click <b>↻ Load</b> to fetch the
            LoginAccount table from the device.
          </div>
        ) : (
          <table className="dense acct-table">
            <thead>
                <tr>
                  <th>#</th>
                  <th>User</th>
                  <th>Group</th>
                  <th>Permission</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => {
                  const group = effective(`${acctBase}${a.inst}.Group`, a.fields.Group?.value);
                  const perms = permSet(
                    effective(`${acctBase}${a.inst}.Permission`, a.fields.Permission?.value),
                  );
                  return (
                    <tr key={a.inst}>
                      <td className="mut">{a.inst}</td>
                      <td className="val">{acctLabel(a)}</td>
                      <td>
                        <span className="seg">
                          {GROUPS.map((g) => (
                            <button
                              key={g}
                              type="button"
                              className={group === g ? "on" : ""}
                              aria-pressed={group === g}
                              onClick={() => setGroup(a, g)}
                            >
                              {g}
                            </button>
                          ))}
                        </span>
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
                      <td className="acct-actions">
                        <button
                          type="button"
                          className="sm"
                          aria-label="account actions"
                          onClick={() => setOpenMenu(openMenu === a.inst ? null : a.inst)}
                        >
                          ⋮
                        </button>
                        {openMenu === a.inst && (
                          <div className="acct-menu">
                            <button type="button" onClick={() => { makeAdmin(a); setOpenMenu(null); }}>
                              ⬆ admin + shell
                            </button>
                            <button type="button" onClick={() => { changePassword(a); setOpenMenu(null); }}>
                              change password
                            </button>
                            <button type="button" onClick={() => { rename(a); setOpenMenu(null); }}>
                              rename (FullName)
                            </button>
                            <button
                              type="button"
                              className="del"
                              onClick={() => { delAccount(a); setOpenMenu(null); }}
                            >
                              delete account
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
        )}
        {openMenu !== null && (
          <div className="acct-backdrop" onClick={() => setOpenMenu(null)} aria-hidden="true" />
        )}

        <div className="set-hint mut">
          Changes are queued and apply when the CPE next processes the queue (use
          <b> 📡 Apply now</b> to push immediately). Group / permission changes and
          new accounts need a <b>reboot</b> before <code>sh</code> works.
        </div>
      </div>

      {showCreate && (
        <div className="modal-backdrop center" onClick={() => setShowCreate(false)}>
          <div
            className="modal acct-modal"
            role="dialog"
            aria-label="Create account"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-head">
              <h2>＋ Create account</h2>
              <button
                type="button"
                className="sm"
                aria-label="close"
                onClick={() => setShowCreate(false)}
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div className="acct-mgrid">
                <label>Username</label>
                <input
                  value={newUser}
                  placeholder="myadmin"
                  onInput={(e) => setNewUser((e.target as HTMLInputElement).value)}
                />
                <label>Password</label>
                <span className="acct-pwrow">
                  <input
                    type={showPass ? "text" : "password"}
                    value={newPass}
                    placeholder="password"
                    onInput={(e) => setNewPass((e.target as HTMLInputElement).value)}
                  />
                  <button type="button" className="acct-pwbtn" onClick={() => setNewPass(genPassword())}>
                    🎲 generate
                  </button>
                  <button
                    type="button"
                    className="acct-pwbtn"
                    aria-label={showPass ? "hide password" : "show password"}
                    onClick={() => setShowPass((v) => !v)}
                  >
                    {showPass ? "🙈" : "👁"}
                  </button>
                </span>
                <label>Group</label>
                <span className="seg">
                  {GROUPS.map((g) => (
                    <button
                      key={g}
                      type="button"
                      className={newGroup === g ? "on" : ""}
                      aria-pressed={newGroup === g}
                      onClick={() => setNewGroup(g)}
                    >
                      {g}
                    </button>
                  ))}
                </span>
                <label>Access</label>
                <span className="grp">
                  {PERMS.map((tok) => (
                    <button
                      key={tok}
                      type="button"
                      className={"chip" + (newPerm.has(tok) ? " on" : "")}
                      aria-pressed={newPerm.has(tok)}
                      onClick={() => toggleNewPerm(tok)}
                    >
                      {tok}
                    </button>
                  ))}
                </span>
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="sm" onClick={() => setShowCreate(false)}>
                Cancel
              </button>
              <button type="button" className="sm acc" onClick={() => void createAccount()}>
                ＋ Create account
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
