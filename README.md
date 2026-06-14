# rv6699-acs (Rust + React) — a full TR-069 (CWMP) ACS for your Sercomm/МГТС RV6699

A self-contained **Rust + React** Auto-Configuration Server that lets you manage
your own **RV6699** (RV6688v2, МГТС sc3.3.46) over the same TR-069 / port-7547
protocol the carrier ACS (`acs.mgts-spdop.ru`) uses. It speaks exactly what the
box expects — `urn:dslforum-org:cwmp-1-0`, SOAP 1.1, HTTP Digest, **chunked**
request bodies, the empty-POST continuation, and a `204` to end sessions — an
envelope verified byte-for-byte against the device's own `cwmp` firmware client.

Two servers run side by side:

| Server | Port | What it is |
|--------|------|------------|
| **CWMP endpoint** | `7547` | point the router's **ACS URL** here |
| **Web console** | `7548` | React UI + REST API + `Download`/`Upload` file server |

There is **no shell entrypoint** — the binary reads every setting from an env var
(via `clap`), so the container is configured purely through the environment.

The React console is **embedded inside the binary** (`rust-embed`), so the whole
app is **one self-contained executable** — no `frontend/dist` folder to ship.
Copy the single binary anywhere and run it.

> ⚠️ Point this **only at a router you own.** It is built for an authorized
> home-lab on your own RV6699 / LAN.

---

## 1. Quick start (Docker) — zero config

```bash
docker compose up -d --build
docker compose logs acs        # <- the first-run admin password is printed here
```

No `.env`, no IP, nothing to set. On first run the ACS **generates a random admin
password and prints it** in the logs (the console is never open-by-default):

```
  FIRST-RUN ADMIN LOGIN
  user=admin  password=249b86b63937  (change it in Settings)
```

Open `http://<your-server>:7548/`, log in with that, and configure **everything
from the ⚙ Settings panel** (see §4). Point the router's ACS URL at
`http://<your-server>:7547/` — the advertise host the router needs for file
transfers is **auto-derived** from the router's own request, so there is no IP to
specify.

### Configuration — in the web console

All settings live in **⚙ Settings** (persisted to `data/settings.json`): the
admin login, whether the router must authenticate (and its password), capture
mode + challenge, Connection-Request creds, and an optional advertise-host
override. Change them live; no restart, no rebuild.

> **Optional env overrides.** If you'd rather pin something without the UI, every
> setting also has an env var you can set in `docker-compose.yml` (`ADVERTISE_IP`,
> `CONSOLE_USER`, `CONSOLE_PASS`, `ACS_USER`, `ACS_PASS`, `CR_USER`, `CR_PASS`,
> `CAPTURE`, `CHALLENGE`, `HOST`, `CWMP_PORT`, `CONSOLE_PORT`). An env value seeds
> the initial setting; UI changes are saved to `settings.json` and win after that.

### Volumes (persist these)

```
./data     -> /app/data       devices.json + settings.json + captures.jsonl
./files    -> /app/files       drop firmware/config here to push via Download
./uploads  -> /app/uploads     configs the router Uploads land here
```

`./data` holds your settings and captured credentials — keep it on a real volume.

---

## 2. Deploying to a public host (VPS / cloud)

This ACS needs **two raw-TCP ports reachable from the internet**, so deploy it on
a **VPS** (Hetzner, DigitalOcean, a cloud VM…) — *not* a single-port HTTP-only
PaaS. The router on your home line connects **out** to your server.

**Checklist:**

1. **The advertise host is automatic** — the router tells the ACS which
   host/domain it used (via the HTTP `Host` header), and file URLs are built from
   that. Just point the router at your domain (`http://acs.example.com:7547/`);
   nothing to set. (You *can* pin it in ⚙ Settings → Advertise host, or via
   `ADVERTISE_IP`, if you ever need to.)
2. **Open the firewall for `7547/tcp`** (the router → ACS). On the cloud console /
   `ufw`: `ufw allow 7547/tcp`. The router won't reach the ACS otherwise.
3. **The console is protected by default.** First run prints a random admin
   password in `docker compose logs`; log in and set your own in ⚙ Settings. The
   UI and `/api` require that login; `/files` and `/upload` stay open on `:7548`
   so the **router** can fetch/push files without credentials.
   - Tightest option: don't expose `:7548` widely — `ufw allow from <your-ip> to any port 7548`, or front it with a TLS reverse proxy (below). But keep `:7548/files` reachable by the router, or `Download`/`Upload` break.
4. **Require the router to authenticate.** In ⚙ Settings tick *"Require the router
   to authenticate"* and set the ACS password (match it in the router UI) so a
   random scanner hitting `:7547` can't drive your router. Or turn on **Capture**
   *first* to learn the password the router already uses (section 5).
5. **TLS (recommended for the console).** Plain HTTP sends the console Basic-auth
   and the captured credentials in the clear. Put a reverse proxy (Caddy/Traefik/
   nginx) with a Let's Encrypt cert in front of `:7548`. Example Caddy:
   ```
   acs.example.com {
       reverse_proxy 127.0.0.1:7548
   }
   ```
   Leave the **CPE side (`:7547`) on plain HTTP** — the RV6699 validates ACS TLS
   against a baked-in CA bundle (DigiCert/Thawte), so a Let's Encrypt cert won't
   necessarily be trusted. Plain HTTP on `:7547` is the pragmatic, working path.
6. **Connection Requests usually won't work from a VPS.** The 📡 button needs the
   ACS to reach the router's WAN `:7547`, but МГТС's GPON puts the router behind
   carrier NAT/firewall, so inbound to it is typically blocked. **Rely on the
   router's Periodic Inform** instead (lower the interval to e.g. 60s). Informs
   are outbound from the router and work fine through NAT.
7. **Persist `./data`** (device DB + `captures.jsonl`) on a real volume/disk so it
   survives redeploys.

The default `docker-compose.yml` uses **`network_mode: host`** (Linux): the ACS
binds the host's `:7547`/`:7548` directly — **no port mapping, no NAT** — and the
advertise host auto-derives. Control exposure with the host firewall.

So a VPS deploy is just: open `7547/tcp` (e.g. `ufw allow 7547/tcp`),
`docker compose up -d --build`, read the admin password from
`docker compose logs`, log in, and (recommended) enable ACS auth + TLS. No
`.env`, no IP, no ports block.

> Same compose works on a **LAN box** — host networking means Connection Requests
> (📡) also work on the LAN. On **Docker Desktop (macOS/Windows)** there's no host
> networking: switch to the commented `acs-desktop` service (published `ports:`
> + `ADVERTISE_IP=<host LAN IP>`).

---

## 3. Point the router at this ACS

Router web UI → **Management ▸ TR-069 Client ▸ Basic**:

1. **Record the originals first** to hand the box back to МГТС later: ACS URL
   `http://acs.mgts-spdop.ru:7547`, ACS Username `ag`, Connection Request
   Username `F7QOyhi33VFQ`, Periodic Inform Interval `42496`.
2. Set **ACS URL** → `http://<ADVERTISE_IP>:7547/` (exact, with trailing slash).
3. If you set `ACS_PASS`, set **ACS Username/Password** to match.
4. Lower **Periodic Inform Interval** to `30`–`60`, keep **Periodic Inform =
   Enable** (this is how a hosted ACS stays in touch — see §2.6).
5. **Apply/Save.** Changing the ACS URL arms a `0 BOOTSTRAP`; the router Informs
   your ACS within a minute or two (reboot it if not) and appears in the console.

### Diagnose the first connection (wire log)

For the very first real session, turn on the **wire log** to see exactly what the
router sends and what we reply — enable it in **⚙ Settings → Diagnostics** (or
launch with `--debug-wire` / `DEBUG_WIRE=1`), then open the **🔌 Wire** viewer in
the console. Every CWMP frame is captured (request headers + body, response
status + body) to the viewer and `data/wire.log`. **Credentials are masked**
(`Authorization: Basic <redacted>`), so the log is safe to copy/paste or share.
Clear it with the viewer's *Clear* button (or `DELETE /api/wire`). Turn it off
when you're done — capture is off by default and only buffers responses while on.

A healthy first session looks like: `in POST / (Inform)` → `out 200 InformResponse`
→ `in POST / (len=0)` → `out 204 (session end)`. If you instead see the router
re-Inform or drop after our `200`, the wire log shows precisely which frame it
choked on.

---

## 4. Drive it from the console

Open the console, click the device, then:

- **🔍 Discover data model** — walks the whole `InternetGatewayDevice.` tree and
  caches every parameter.
- **Device info / Wi-Fi / Connected hosts** — one-click reads (SSID +
  `KeyPassphrase`, the `Hosts.` table, optical levels).
- **GetParameterValues… / SetParameterValues…** — arbitrary read/write (a name
  ending in `.` fetches a whole subtree).
- **AddObject / DeleteObject**, **Download…**, **Upload…**, **GetRPCMethods**,
  **Reboot**, **Factory reset**, **📡 Connection Request** (LAN only, see §2.6).

Everything is also a REST API (Basic auth when `CONSOLE_PASS` is set):

```bash
curl -u admin:PASS -X POST http://<host>:7548/api/device/00227F-XXXX/task \
  -H "Content-Type: application/json" \
  -d '{"type":"get","args":{"names":["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase"]}}'
```

---

## 5. Capture the real ACS password the router was provisioned with

The router never shows its stored ACS password (the dots are a fixed mask). But
when it authenticates to *your* ACS you can capture it. In **⚙ Settings** tick
**Capture mode** and pick a challenge, then point the router here and wait for an
Inform. The ACS sends a `401` challenge:

- **Capture / basic** (default) → router replies `Authorization: Basic` =
  **username + password in plaintext**, logged, shown in the 🔑 *Captured ACS
  credentials* banner, and appended to `data/captures.jsonl`.
- **Capture / digest** → if the router refuses Basic, you capture the Digest
  **hash**; crack it offline with [`tools/crack_acs_digest.py`](tools/crack_acs_digest.py).
- **Capture / both** → offer both (router usually picks Digest).

> This captures the *ACS-session* credential (CPE → ACS, user `ag`). The
> *Connection-Request* password can't be captured this way — but you don't need
> the original: set your own in ⚙ Settings → Connection Request + the router UI.

---

## ⚠️ MGTS re-provisioning caveat

While the box is pointed at МГТС, their ACS can rewrite `ManagementServer.URL`
back, push firmware, or reset config at any time. Keep redirect windows short,
**record the originals** (§3.1), and restore them when done. This is your own
device — that's the authorized scope. Don't point a router you don't own here.

---

## How a session works

```
CPE  --POST Inform (chunked)----------->  ACS   (auth if ACS_PASS set)
CPE  <--200 InformResponse + cookie----  ACS
CPE  --POST (empty)-------------------->  ACS   "your turn"
CPE  <--200 GetParameterValues---------  ACS   (one queued RPC)
CPE  --POST GetParameterValuesResponse->  ACS   (result cached)
CPE  <--204 No Content-----------------  ACS   queue empty -> session ends
```

Mandatory `cwmp:ID` echo with `mustUnderstand`, namespace mirrored from the CPE's
Inform, an envelope **byte-faithful to the device** (uppercase `SOAP-ENV`, no
`encodingStyle` — verified against the firmware), chunked de-framing, charset per
`Content-Type`, atomic `SetParameterValues` with per-parameter `9xxx` fault
parsing, and the symmetric empty-body = "done" rule. Sessions are correlated by
the `ACSSESSION` cookie (axum is per-request, not per-connection) with a
client-IP fallback.

---

## Build it natively (single binary)

```bash
cd frontend && npm ci && npm run build && cd ..   # build the console first…
cargo build --release                             # …it gets embedded into the binary
./target/release/rv6699-acs                        # one file, no dist folder needed
```

> The console is embedded at compile time, so `frontend/dist` must exist **before**
> `cargo build` (build the frontend first, as above — or just use Docker, which
> does it for you). `--web-dir <dir>` overrides the embedded copy with on-disk
> serving for live frontend development.

## Project layout

```
.
  Dockerfile               multi-stage: frontend (Node) -> backend (Rust) -> tiny runtime
  docker-compose.yml       zero-config service 'acs' (network_mode: host, Linux)
  .dockerignore
  Cargo.toml, src/         the Rust ACS — ONE self-contained binary (UI embedded)
    src/settings.rs        runtime-mutable settings (data/settings.json) + /api/settings
  frontend/                React 19 / Vite console (built -> embedded via rust-embed)
  tools/crack_acs_digest.py  offline cracker for a captured Digest hash
  .github/workflows/       CI (build+lint+docker), Docker publish (GHCR), release binary
```

## CI / images / releases

- **CI** (`.github/workflows/ci.yml`) — on every push/PR: builds the frontend,
  `cargo fmt --check`, `clippy -D warnings`, release build, and a Docker build.
- **Docker image** (`docker-publish.yml`) — pushes to
  `ghcr.io/<owner>/acs-console` on `main` and version tags. Pull and run:
  `docker run --network host ghcr.io/<owner>/acs-console`.
- **Release binary** (`release.yml`) — tag `vX.Y.Z` to publish a fully-static
  single Linux binary (musl, console embedded) on the GitHub Release.

## License

[Apache-2.0](LICENSE).
