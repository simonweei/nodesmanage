import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const migrations = await readD1Migrations("./migrations");

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: "./wrangler.jsonc" },
    miniflare: { bindings: {
      TEST_MIGRATIONS: migrations,
      ADMIN_PASSWORD: "test-admin-password-with-32-chars",
      AGENT_TOKEN_SECRET: "test-agent-secret-with-at-least-32-characters",
    } },
  })],
  test: { include: ["test/**/*.test.ts"] },
});
