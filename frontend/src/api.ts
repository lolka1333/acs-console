import type {
  AcsState,
  ConnReqResponse,
  DeviceDetail,
  DiscoverResponse,
  Settings,
  SettingsUpdate,
  TaskResponse,
  WireResponse,
} from "./types";

async function api<T>(
  path: string,
  method: "GET" | "POST" | "PUT" | "DELETE" = "GET",
  body?: unknown,
): Promise<T> {
  const o: RequestInit = { method, headers: {} };
  if (body !== undefined) {
    o.headers = { "Content-Type": "application/json" };
    o.body = JSON.stringify(body);
  }
  const r = await fetch(path, o);
  return (await r.json()) as T;
}

export function getState(): Promise<AcsState> {
  return api<AcsState>("/api/state");
}

export function getDevice(key: string): Promise<DeviceDetail> {
  return api<DeviceDetail>("/api/device/" + encodeURIComponent(key));
}

export function getSettings(): Promise<Settings> {
  return api<Settings>("/api/settings");
}

// Send only the changed fields. Absent = unchanged; "" = clear/disable.
export function putSettings(patch: SettingsUpdate): Promise<Settings> {
  return api<Settings>("/api/settings", "PUT", patch);
}

export function postTask(
  key: string,
  type: string,
  args: Record<string, unknown>,
  label: string,
): Promise<TaskResponse> {
  return api<TaskResponse>(
    "/api/device/" + encodeURIComponent(key) + "/task",
    "POST",
    { type, args, label },
  );
}

export function postConnReq(key: string): Promise<ConnReqResponse> {
  return api<ConnReqResponse>(
    "/api/device/" + encodeURIComponent(key) + "/connreq",
    "POST",
    {},
  );
}

export function postDiscover(
  key: string,
  body: { path?: string; max_depth?: number; max_nodes?: number },
): Promise<DiscoverResponse> {
  return api<DiscoverResponse>(
    "/api/device/" + encodeURIComponent(key) + "/discover",
    "POST",
    body,
  );
}

// ---- Diagnostic wire log ----
export function getWire(): Promise<WireResponse> {
  return api<WireResponse>("/api/wire");
}

export function clearWire(): Promise<{ ok: boolean }> {
  return api<{ ok: boolean }>("/api/wire", "DELETE");
}
