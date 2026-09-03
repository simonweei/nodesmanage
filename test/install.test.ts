import { describe, expect, it } from "vitest";
import { installScript } from "../src/install";
import { installManifest } from "../src/releases";
import { hmacHex } from "../src/crypto";
import { minimalInstallScript } from "../src/minimal-install";

describe("portable bootstrap", () => {
  it("renders an Agent-free minimal installer with automatic privilege and service detection", async () => {
    const response = minimalInstallScript({
      origin: "https://manage.example.com",
      ticket: "minimal-ticket",
      settings: {
        listen_port: 8443,
        shared_uuid: "11111111-2222-4333-8444-555555555555",
        server_name: "www.cloudflare.com",
        reality_handshake_server: "www.cloudflare.com",
        reality_handshake_port: 443,
        reality_private_key: "private-key",
        reality_short_id: "aabbccdd",
      },
    });
    const script = await response.text();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(script).toContain('if [ "$(id -u)" -eq 0 ]');
    expect(script).toContain("port $LISTEN_PORT requires root");
    expect(script).toContain("systemctl --user");
    expect(script).toContain("rc-service nodemanage-minimal restart");
    expect(script).toContain("start_standalone");
    expect(script).toContain("GOMEMLIMIT=64MiB");
    expect(script).not.toContain("GOGC=");
    expect(script).toContain('"uuid": "11111111-2222-4333-8444-555555555555"');
    expect(script).toContain("/api/minimal/complete");
    expect(script).not.toContain("nodemanage-agent");
  });

  it("only verifies and hands installation to the Agent", async () => {
    const script = await installScript("https://manage.example.com").text();
    expect(script).toContain("--ticket");
    expect(script).toContain("command -v curl");
    expect(script).toContain("command -v wget");
    expect(script).toContain("busybox wget");
    expect(script).toMatch(/EXPECTED='[a-f0-9]{64}'/);
    expect(script).not.toContain("SHA256SUMS");
    expect(script).toContain("nodemanage-agent\" install");
    expect(script).toContain("--mode");
    expect(script).toContain("CONNECT_PORT='443'");
    expect(script).toContain('--connect-port) CONNECT_PORT="${2:-}"');
    expect(script).toContain('--connect-port "$CONNECT_PORT"');
    expect(script).toContain("user mode must run without sudo");
    expect(script).not.toContain("run this installer as root");
    expect(script).not.toContain("systemctl");
    expect(script).not.toContain("github.com/SagerNet");
  });

  it("returns a pinned, checksummed release", async () => {
    const response = installManifest(new Request("https://manage.example.com/api/install/manifest?os=linux&arch=arm64"));
    const manifest = await response.json() as { schema_version: number; agent: { urls: string[]; sha256: string }; sing_box: { version: string; urls: string[]; sha256: string }; cloudflared: { version: string; urls: string[]; sha256: string } };
    expect(manifest.schema_version).toBe(2);
    expect(manifest.agent.urls).toEqual(["https://manage.example.com/downloads/v0.11.0/nodemanage-agent-linux-arm64"]);
    expect(manifest.agent.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest.sing_box).toMatchObject({ version: "1.13.12" });
    expect(manifest.sing_box.urls[0]).toContain("manage.example.com/downloads/v1.13.12/");
    expect(manifest.sing_box.urls[1]).toContain("github.com/SagerNet/");
    expect(manifest.sing_box.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest.cloudflared).toMatchObject({ version: "2026.8.2" });
    expect(manifest.cloudflared.urls[0]).toContain("github.com/cloudflare/cloudflared/releases/download/2026.8.2/");
    expect(manifest.cloudflared.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("derives stable and separated idempotent credentials", async () => {
    const secret = "test-only-secret-with-at-least-32-characters";
    const first = await hmacHex(secret, "agent-id:ticket:installer-claim");
    expect(await hmacHex(secret, "agent-id:ticket:installer-claim")).toBe(first);
    expect(await hmacHex(secret, "agent-token:ticket:installer-claim")).not.toBe(first);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });
});
