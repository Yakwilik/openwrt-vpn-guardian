import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: resolve(__dirname, "../internal/api/web/dist"),
    emptyOutDir: true,
    sourcemap: false,
    target: "es2022",
  },
});
