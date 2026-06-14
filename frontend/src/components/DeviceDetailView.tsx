import type { DeviceDetail, LogEntry } from "../types";
import Actions from "./Actions";
import CapturesBanner from "./CapturesBanner";
import DeviceIdentity from "./DeviceIdentity";
import EventLog from "./EventLog";
import ParametersTable from "./ParametersTable";
import TaskHistory from "./TaskHistory";

interface Props {
  device: DeviceDetail;
  captures: DeviceDetail["captures"];
  log: LogEntry[];
  filter: string;
  onFilter: (v: string) => void;
  onChanged: () => void;
}

export default function DeviceDetailView({
  device,
  captures,
  log,
  filter,
  onFilter,
  onChanged,
}: Props) {
  return (
    <>
      <CapturesBanner captures={captures} />
      <DeviceIdentity device={device} />
      <Actions device={device} onChanged={onChanged} />
      <ParametersTable
        parameters={device.parameters || []}
        filter={filter}
        onFilter={onFilter}
      />
      <TaskHistory history={device.history || []} />
      <div className="card">
        <h2>Event log</h2>
        <div className="body">
          <EventLog log={log} />
        </div>
      </div>
    </>
  );
}
