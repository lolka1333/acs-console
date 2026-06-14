import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build to ./dist (Vite default) with relative asset paths so the bundle can be
// served from "/" by the Rust console server. Dev server proxies the API,
// file-download and upload paths to the running ACS console (default :7548).
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:7548",
      "/files": "http://localhost:7548",
      "/upload": "http://localhost:7548",
    },
  },
});
