import type { LogEntry } from "../types";
import { prettyTs } from "../util";

interface Props {
  log: LogEntry[];
}

export default function EventLog({ log }: Props) {
  const rows = (log || []).slice().reverse().slice(0, 200);
  return (
    <div className="log">
      {rows.map((l, i) => (
        <div key={i} className={"l " + (l.level || "info")}>
          <span className="ts">{prettyTs(l.ts)}</span>{" "}
          {l.key ? "[" + l.key + "] " : ""}
          {l.msg}
        </div>
      ))}
    </div>
  );
}
