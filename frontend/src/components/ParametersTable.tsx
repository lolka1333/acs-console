import { useMemo } from "react";
import type { Param } from "../types";
import { shortType } from "../util";

interface Props {
  parameters: Param[];
  filter: string;
  onFilter: (v: string) => void;
}

export default function ParametersTable({ parameters, filter, onFilter }: Props) {
  const shown = useMemo(() => {
    if (!filter) return parameters;
    const f = filter.toLowerCase();
    return parameters.filter(
      (p) =>
        p.name.toLowerCase().includes(f) ||
        String(p.value).toLowerCase().includes(f),
    );
  }, [parameters, filter]);

  return (
    <div className="card">
      <h2>
        Parameters{" "}
        <span className="pill">
          {shown.length} shown / {parameters.length} known
        </span>
      </h2>
      <div className="body">
        <input
          className="filter wide"
          placeholder="filter by name or value…"
          value={filter}
          onInput={(e) => onFilter((e.target as HTMLInputElement).value)}
        />
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Value</th>
                <th>Type</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 1500).map((p) => (
                <tr key={p.name}>
                  <td>{p.name}</td>
                  <td className="val">{p.value}</td>
                  <td className="mut">{shortType(p.type)}</td>
                  <td>
                    {p.writable === "1" ? (
                      <span className="tag w">rw</span>
                    ) : p.writable === "0" ? (
                      <span className="tag">ro</span>
                    ) : null}
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
