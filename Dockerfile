# syntax=docker/dockerfile:1
#
# rv6699-acs — multi-stage build (no shell scripts; configured purely via env)
#   stage 1 (frontend) : build the React/Vite console -> frontend/dist
#   stage 2 (backend)  : build the Rust release binary -> rv6699-acs
#   stage 3 (runtime)  : slim Debian image with binary + built web assets
#
# The binary reads every flag from an env var (clap `env`), so there is NO
# entrypoint shell script — the container is configured entirely through the
# environment (see docker-compose.yml). The CWMP endpoint is :7547 (point the
# router here) and the web console + REST + file server is :7548.

# ---------------------------------------------------------------------------
# Stage 1 — frontend: build the Vite app into static assets
# ---------------------------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /app/frontend

# Install deps first (cached unless the manifests change).
COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# Build the production bundle -> /app/frontend/dist
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — backend: build the Rust release binary
# ---------------------------------------------------------------------------
FROM rust:1.96-bookworm AS backend
WORKDIR /app

# Fetch dependencies first so they cache across source-only changes.
COPY Cargo.toml ./
COPY Cargo.lock* ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo fetch

# Real sources + the built console (rust-embed bakes frontend/dist INTO the
# binary, so the result is a single self-contained executable).
COPY src/ ./src/
COPY --from=frontend /app/frontend/dist ./frontend/dist
RUN cargo build --release --bin rv6699-acs \
    && strip target/release/rv6699-acs || true

# ---------------------------------------------------------------------------
# Stage 3 — runtime: minimal image with JUST the single self-contained binary
# (the console is embedded inside it — no separate web assets to copy).
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: outbound TLS if ever needed.  tini: a tiny C init (NOT a
# shell) that reaps zombies and forwards SIGTERM so `docker stop` is clean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The compiled ACS — UI baked in, so this single file is the whole app.
COPY --from=backend  /app/target/release/rv6699-acs  /usr/local/bin/rv6699-acs

# Runtime data lives under /app (mount these as volumes to persist).
RUN mkdir -p /app/data /app/files /app/uploads

# Fixed in-container paths; everything else is configured via env at run time
# (ADVERTISE_IP, ACS_PASS, CONSOLE_USER/CONSOLE_PASS, CAPTURE, CHALLENGE, ...).
ENV DATA_DIR=/app/data \
    FILES_DIR=/app/files \
    UPLOADS_DIR=/app/uploads

# CWMP (router -> ACS) and console (browser + REST + files).
EXPOSE 7547 7548

# Direct exec of the binary under tini — no shell involved. Extra args passed to
# `docker run <image> --flag` are appended to the binary verbatim.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/rv6699-acs"]
