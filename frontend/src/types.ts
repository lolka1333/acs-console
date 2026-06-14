// Types mirroring the ACS console REST contract (see console.py / store.py).

export interface InformEvent {
  code: string;
  command_key?: string;
}

export interface LastInform {
  ts: string;
  events: InformEvent[];
  source: string;
}

export type TaskStatus = "pending" | "inflight" | "done" | "fault" | "error";

export interface SetFault {
  name: string;
  code: string | number;
}

export interface TaskFault {
  code?: string | number;
  string?: string;
  set_faults?: SetFault[];
  [k: string]: unknown;
}

export interface TaskResultParam {
  name: string;
  value: string;
  type?: string;
}

export interface TaskResult {
  parameters?: TaskResultParam[];
  names?: { name: string; writable?: string }[];
  status?: number | string | null;
  instance_number?: number | string | null;
  methods?: string[];
  [k: string]: unknown;
}

export interface Task {
  id: number;
  type: string;
  args: Record<string, unknown>;
  label: string;
  status: TaskStatus;
  result: TaskResult | null;
  fault: TaskFault | null;
  created: string;
  updated: string;
  walk_id: number | null;
}

export interface Capture {
  scheme: "basic" | "digest";
  username: string;
  password?: string;
  response?: string;
  realm?: string;
  nonce?: string;
  nc?: string;
  cnonce?: string;
  qop?: string;
  uri?: string;
  ts: string;
  key: string;
}

export interface DeviceView {
  key: string;
  oui: string;
  serial: string;
  product_class: string;
  manufacturer: string;
  model: string;
  software_version: string;
  ip: string;
  cwmp_ns: string;
  root: string;
  connection_request_url: string;
  last_inform: LastInform | null;
  last_seen: string;
  online_hint: boolean;
  param_count: number;
  queue: Task[];
  history: Task[];
  captures: Capture[];
  rpc_methods?: string[];
}

export interface Param {
  name: string;
  value: string;
  type: string;
  writable: string;
  ts: string;
}

export interface Attr {
  name: string;
  notification: string;
  access_list: string[];
}

export interface DeviceDetail extends DeviceView {
  parameters: Param[];
  attributes: Attr[];
}

export interface LogEntry {
  ts: string;
  msg: string;
  key: string | null;
  level: "info" | "warn" | "error";
}

export interface StateConfig {
  advertise_ip: string;
  cwmp_port: number;
  console_port: number;
  acs_username: string;
  auth: string;
  cr_username: string;
  acs_url: string;
  // Added by the runtime-settings work: first-run / auto-advertise hints.
  needs_setup: boolean;
  advertise_effective: string;
  console_auth: boolean;
}

// GET /api/settings — server NEVER returns real passwords, only *_set booleans.
export interface Settings {
  acs_username: string;
  acs_auth_enabled: boolean;
  capture: boolean;
  challenge: "basic" | "digest" | "both";
  cr_username: string;
  cr_password_set: boolean;
  console_username: string;
  console_password_set: boolean;
  console_password_generated: boolean;
  advertise_host: string;
  advertise_effective: string;
  needs_setup: boolean;
  // Diagnostics: raw CWMP wire-frame capture toggle.
  debug_wire: boolean;
  ports: { cwmp: number; console: number };
}

// PUT /api/settings — every field optional. Absent = leave unchanged;
// present (even "") = set to that value.
export interface SettingsUpdate {
  acs_username?: string;
  acs_password?: string;
  console_username?: string;
  console_password?: string;
  capture?: boolean;
  challenge?: "basic" | "digest" | "both";
  cr_username?: string;
  cr_password?: string;
  advertise_host?: string;
  debug_wire?: boolean;
}

export interface AcsState {
  devices: DeviceView[];
  log: LogEntry[];
  captures: Capture[];
  config: StateConfig;
}

export interface TaskResponse {
  queued: number;
  pending: number;
}

export interface ConnReqResponse {
  ok: boolean;
  detail: string;
  url: string;
}

export interface DiscoverResponse {
  walk_id: number;
  queued: number;
}

// ---- Diagnostic wire log (GET/DELETE /api/wire) ----
// One captured CWMP frame. dir "in" = a request the CPE sent us;
// dir "out" = a response we sent the CPE.
export interface WireEntry {
  id: number;
  ts: string;
  dir: "in" | "out";
  client_ip: string;
  session_key: string | null;
  summary: string;
  headers: Record<string, string>;
  body: string;
}

export interface WireResponse {
  enabled: boolean;
  entries: WireEntry[];
}
