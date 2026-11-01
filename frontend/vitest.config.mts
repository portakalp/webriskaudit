import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

const root = fileURLToPath(new URL(".", import.meta.url))

export default defineConfig({
  resolve: {
    alias: [{ find: /^@\//, replacement: root }],
  },
  test: {
    environment: "jsdom",
    include: ["**/*.test.{ts,tsx}"],
    exclude: ["node_modules/**", ".next/**", "out/**"],
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
  },
})
