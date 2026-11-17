import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The page is built into the Python package, so the API server can serve it and one
// address shows everything. Asset paths are relative, so it also works under a sub-path.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "../src/nettriage/api/static",
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` serves the page with hot reload and passes API calls on to the server.
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
