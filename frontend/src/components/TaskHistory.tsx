import type { Task } from "../types";
import { summarize } from "../util";

interface Props {
  history: Task[];
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
                  <td className="val">{summarize(t)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
