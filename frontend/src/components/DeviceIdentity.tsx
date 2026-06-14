import type { DeviceDetail } from "../types";
import { paramByLeaf, prettyTs } from "../util";

interface Props {
  device: DeviceDetail;
}

export default function DeviceIdentity({ device: d }: Props) {
  const r = d.root || "InternetGatewayDevice.";
  const ev = (d.last_inform?.events || []).map((e) => e.code).join(", ");
  const sw = d.software_version || paramByLeaf(d, "SoftwareVersion");
  const rpc = (d.rpc_methods || []).join(", ") || "(run GetRPCMethods)";
  return (
    <div className="card">
      <h2>
        {d.product_class || d.model || d.key} <span className="pill">{d.key}</span>
      </h2>
      <div className="body">
        <div className="kv">
          <div>Manufacturer / OUI</div>
          <div>
            {d.manufacturer} / {d.oui}
          </div>
          <div>Serial</div>
          <div>{d.serial}</div>
          <div>Software</div>
          <div>{sw}</div>
          <div>Source IP</div>
          <div>{d.ip}</div>
          <div>Data-model root</div>
          <div>{r}</div>
          <div>cwmp namespace</div>
          <div>{d.cwmp_ns}</div>
          <div>ConnectionRequestURL</div>
          <div>
            {d.connection_request_url ||
              "(unknown — appears after first Inform)"}
          </div>
          <div>Last Inform</div>
          <div>
            {prettyTs(d.last_inform?.ts)} · events: {ev}
          </div>
          <div>CPE-supported RPCs</div>
          <div>{rpc}</div>
        </div>
      </div>
    </div>
  );
}
