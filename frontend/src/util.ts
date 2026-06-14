import type { DeviceDetail, Task } from "./types";

// "2026-06-14T12:00:00Z" -> "2026-06-14 12:00:00"
export function prettyTs(ts: string | null | undefined): string {
  return String(ts ?? "").replace("T", " ").replace("Z", "");
}

// Find a parameter by its leaf suffix (used as a fallback for SoftwareVersion).
export function paramByLeaf(d: DeviceDetail, leaf: string): string {
  const p = (d.parameters || []).find((x) => x.name.endsWith(leaf));
  return p ? p.value : "";
}

// One-line summary of a finished task's result/fault — ported from index.html.
export function summarize(t: Task): string {
  if (t.fault) {
    const f = t.fault;
    const sf =
      f.set_faults && f.set_faults.length
        ? " [" + f.set_faults.map((x) => x.name + ":" + x.code).join(", ") + "]"
        : "";
    return "FAULT " + (f.code ?? "") + " " + (f.string ?? "") + sf;
  }
  const r = t.result || {};
  if (r.parameters)
    return (
      r.parameters.length +
      " value(s): " +
      r.parameters
        .slice(0, 3)
        .map((p) => p.name.split(".").slice(-2).join(".") + "=" + p.value)
        .join(", ") +
      (r.parameters.length > 3 ? " …" : "")
    );
  if (r.names) return r.names.length + " name(s)";
  if (r.status != null)
    return "Status " + r.status + (r.instance_number ? " instance " + r.instance_number : "");
  if (r.methods) return r.methods.join(", ");
  return JSON.stringify(r).slice(0, 120);
}

// Normalise xsd:string -> string for the type column.
export function shortType(type: string | undefined): string {
  return (type || "").replace("xsd:", "");
}
