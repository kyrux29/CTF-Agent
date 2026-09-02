import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Keep test-only plugins, discovery, and browser shims outside the Web product.
// This config executes from the dedicated tests workspace root.
export default defineConfig({
  plugins: [react()],
  test: {
    css: true,
    environment: "jsdom",
    include: ["web/**/*.test.{ts,tsx}"],
    setupFiles: "web/setup.ts",
  },
});
