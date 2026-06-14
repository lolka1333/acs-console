import type { DeviceView } from "../types";
import { prettyTs } from "../util";

interface Props {
  devices: DeviceView[];
  selected: string | null;
  onSelect: (key: string) => void;
}

export default function DeviceList({ devices, selected, onSelect }: Props) {
  if (!devices.length) {
    return (
      <div className="side">
        <div className="dev s">no devices yet…</div>
      </div>
    );
  }
  return (
    <div className="side">
      {devices.map((d) => (
        <div
          key={d.key}
          className={"dev" + (d.key === selected ? " sel" : "")}
          onClick={() => onSelect(d.key)}
        >
          <div className="n">
            <span className={"dot" + (d.online_hint ? " on" : "")} />
            {d.product_class || d.model || d.key}
          </div>
          <div className="s">
            {(d.serial || d.key) + " · " + (d.ip || "")}
          </div>
          <div className="s">
            {d.param_count} params · {(d.queue || []).length} queued · seen{" "}
            {prettyTs(d.last_seen)}
          </div>
        </div>
      ))}
    </div>
  );
}
