import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  optimizeDeps: {
    exclude: ["argon2-browser"],
    esbuildOptions: {
      target: "esnext",
    },
  },
  build: {
    target: "esnext",
  },
  test: {
    // Enable browser mode
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [
        {
          browser: "chromium",
          headless: true,
        },
      ],
    },
    // Test environment settings
    globals: false,
    // Timeout for browser tests (crypto operations can be slower in browser)
    testTimeout: 30000,
    hookTimeout: 30000,
    // Reporter
    reporters: ["verbose"],
    // Include test files
    include: ["**/*.test.ts", "test.ts"],
  },
});
