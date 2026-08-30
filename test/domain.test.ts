import { describe, expect, it } from "vitest";
import { handleAdminAuth, hasAdminSession, requireAdmin } from "../src/auth";
import { compileServerConfig, compileServerProfiles, parseProfileSettings, type ProfileSettings, type ProfileType } from "../src/domain";
import { readJsonObject } from "../src/http";
import { mihomoSubscription, singBoxSubscription, uriSubscription } from "../src/subscriptions";

const client = {
  id: "client-1", name: "Alice", uuid: "11111111-1111-4111-8111-111111111111",
  shadowsocks_password: "dXNlci1rZXktMTIzNA==",
};
const cases: [ProfileType, ProfileSettings, string][] = [
  ["vless-reality-vision", { listen_port: 443, server_name: "www.microsoft.com", reality_private_key: "private", reality_public_key: "public", reality_short_id: "0123456789abcdef", reality_handshake_server: "www.microsoft.com", reality_handshake_port: 443 }, "vless"],
  ["shadowsocks-aead", { listen_port: 8388, shadowsocks_method: "2022-blake3-aes-128-gcm", shadowsocks_server_password: "c2VydmVyLWtleS0xMjM=" }, "shadowsocks"],
];

describe("production Protocol Profiles", () => {
  it.each(cases)("parses and compiles %s", (type, settings, inboundType) => {
    const parsed = parseProfileSettings(type, settings);
    const inbound = (compileServerConfig(type, parsed, [client]).inbounds as Record<string, unknown>[])[0];
    expect(inbound).toMatchObject({ type: inboundType, listen_port: settings.listen_port });
  });

  it("keeps security-sensitive fixed choices", () => {
    const ss = (compileServerConfig("shadowsocks-aead", cases[1][1], [client]).inbounds as Record<string, unknown>[])[0];
    expect(ss).toMatchObject({ network: "tcp", multiplex: { enabled: true } });
  });

  it("rejects invalid ports and short IDs", () => {
    expect(() => parseProfileSettings("shadowsocks-aead", { ...cases[1][1], listen_port: 70000 })).toThrow("valid port");
    expect(() => parseProfileSettings("vless-reality-vision", { ...cases[0][1], reality_short_id: "not-hex" })).toThrow("hexadecimal");
  });
});

describe("subscriptions", () => {
  it.each(cases)("generates sing-box, Mihomo and URI for %s", (type, settings, protocol) => {
    const node = { id: `node-${type}`, name: "Tokyo", address: "node.example.com", type, settings_json: JSON.stringify(settings) };
    expect((JSON.parse(singBoxSubscription(client, [node])).outbounds[0] as { type: string }).type).toBe(protocol);
    expect(mihomoSubscription(client, [node])).toContain("proxies:");
    expect(uriSubscription(client, [node])).toContain("node.example.com");
  });
});

describe("multiple protocols on one VPS", () => {
  it("compiles every selected protocol and expands them in subscriptions", () => {
    const profiles = cases.map(([type, settings]) => ({ type, settings }));
    expect((compileServerProfiles(profiles, [client]).inbounds as unknown[])).toHaveLength(2);
    const node = { id: "multi", name: "Tokyo", address: "node.example.com", type: profiles[0].type, settings_json: JSON.stringify(profiles[0].settings), protocols_json: JSON.stringify(profiles) };
    expect(JSON.parse(singBoxSubscription(client, [node])).outbounds).toHaveLength(2);
    expect(uriSubscription(client, [node]).trim().split("\n")).toHaveLength(2);
  });
});

describe("admin authentication boundary", () => {
  const allow = { limit: async () => ({ success: true }) } as RateLimit;
  const authEnv = { ADMIN_PASSWORD: "correct-horse-battery-staple", LOGIN_RATE_LIMITER: allow };

  it("creates and verifies a signed HttpOnly session", async () => {
    const response = await handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: authEnv.ADMIN_PASSWORD }),
    }), authEnv);
    const setCookie = response.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).toContain("Secure");
    const cookie = setCookie.split(";")[0];
    const request = new Request("https://manage.example.com/api/admin/state", { headers: { cookie } });
    expect(await hasAdminSession(request, authEnv)).toBe(true);
    await expect(requireAdmin(request, authEnv)).resolves.toBeUndefined();
  });

  it("rejects wrong passwords and Access headers without a session", async () => {
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "wrong-password" }),
    }), authEnv)).rejects.toThrow("密码错误");
    await expect(requireAdmin(new Request("https://manage.example.com/api/admin/state", {
      headers: { "cf-access-authenticated-user-email": "admin@example.com" },
    }), authEnv)).rejects.toThrow("admin login required");
  });

  it("accepts twelve-character secrets and rejects shorter configuration", async () => {
    const twelveCharacterEnv = { ADMIN_PASSWORD: "abc123456789", LOGIN_RATE_LIMITER: allow };
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "abc123456789" }),
    }), twelveCharacterEnv)).resolves.toMatchObject({ status: 200 });
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "abc12345678" }),
    }), { ADMIN_PASSWORD: "abc12345678", LOGIN_RATE_LIMITER: allow })).rejects.toThrow("at least 12 characters");
  });

  it("returns 429 when the login limiter denies the request", async () => {
    const denied = { limit: async () => ({ success: false }) } as RateLimit;
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: authEnv.ADMIN_PASSWORD }),
    }), { ...authEnv, LOGIN_RATE_LIMITER: denied })).rejects.toMatchObject({ status: 429 });
  });
});

describe("bounded JSON requests", () => {
  it("rejects a streamed body that exceeds the limit without Content-Length", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"value":"'));
        controller.enqueue(new Uint8Array(128));
        controller.enqueue(new TextEncoder().encode('"}'));
        controller.close();
      },
    });
    const request = new Request("https://manage.example.com/api/test", { method: "POST", body: stream });
    await expect(readJsonObject(request, 64)).rejects.toMatchObject({ status: 413 });
  });
});
