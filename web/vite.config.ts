/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// O build vai direto para o diretório embarcado pelo Go (internal/webui).
// Sem recursos embutidos como data: URI, para a CSP do core (default-src 'self') valer sem exceções.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
    target: "es2023",
  },
  server: {
    port: 5173,
    strictPort: true,
    // Em desenvolvimento, a API vem de um core local (vigiahost serve).
    proxy: { "/api": "http://127.0.0.1:8743" },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
  },
});
