import type { Task } from "../types";
import { resultLines, summarize } from "../util";

interface Props {
  history: Task[];
}

// Compact summary by default; click to expand the full name=value list.
function ResultCell({ task }: { task: Task }) {
  const full = resultLines(task);
  if (!full) return <>{summarize(task)}</>;
  return (
    <details className="taskres">
      <summary>{summarize(task)}</summary>
      <pre className="taskres-body">{full}</pre>
    </details>
  );
}

export default function TaskHistory({ history }: Props) {
  const rows = (history || []).slice().reverse().slice(0, 80);
  return (
    <div className="card">
      <h2>Task history</h2>
      <div className="body">
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Task</th>
                <th>Status</th>
                <th>Result / fault</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id}>
                  <td className="mut">{t.id}</td>
                  <td>{t.label}</td>
                  <td>
                    <span className={"st " + t.status}>{t.status}</span>
                  </td>
                  <td className="val">
                    <ResultCell task={t} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
