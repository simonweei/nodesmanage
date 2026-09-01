import { describe, expect, it } from "vitest";
import { handleAdminAuth, hasAdminSession, requireAdmin } from "../src/auth";
import { certificateRequirements, compileServerConfig, compileServerProfiles, ingressCapabilities, parseProfileSettings, profileDefaults, tunnelEdgePort, type ProfileSettings, type ProfileType } from "../src/domain";
import { readJsonObject } from "../src/http";
import { realityKeypair } from "../src/crypto";
import { mihomoSubscription, shadowsocksSubscription, singBoxSubscription, uriSubscription, v2rayNSubscription } from "../src/subscriptions";
import { x25519 } from "@noble/curves/ed25519.js";

const decodeBase64Url = (value: string): Uint8Array => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), (char) => char.charCodeAt(0));

const client = {
  id: "client-1", name: "Alice", uuid: "11111111-1111-4111-8111-111111111111",
  shadowsocks_password: "YWJjZGVmMDEyMzQ1Njc4OQ==",
};
const cases: [ProfileType, ProfileSettings, string][] = [
  ["vless-reality-vision", { listen_port: 443, server_name: "www.microsoft.com", reality_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", reality_public_key: "public", reality_short_id: "0123456789abcdef", reality_handshake_server: "www.microsoft.com", reality_handshake_port: 443 }, "vless"],
  ["shadowsocks-aead", { listen_port: 8388, shadowsocks_method: "2022-blake3-aes-128-gcm", shadowsocks_server_password: "MDEyMzQ1Njc4OWFiY2RlZg==" }, "shadowsocks"],
  ["vless-tls-websocket", { listen_port: 8443, server_address: "ws.example.net", tls_server_name: "ws.example.net", acme_email: "ops@example.net", websocket_path: "/proxy", websocket_host: "ws.example.net" }, "vless"],
  ["vless-tls-grpc", { listen_port: 443, server_address: "grpc.example.net", tls_server_name: "grpc.example.net", acme_email: "ops@example.net", grpc_service_name: "NodeManage" }, "vless"],
  ["hysteria2", { listen_port: 8443, server_address: "hy2.example.net", tls_server_name: "hy2.example.net", acme_email: "ops@example.net", hysteria2_obfs_password: "obfs-secret" }, "hysteria2"],
  ["tuic", { listen_port: 10443, server_address: "tuic.example.net", tls_server_name: "tuic.example.net", acme_email: "ops@example.net" }, "tuic"],
  ["trojan-tls", { listen_port: 9443, server_address: "trojan.example.net", tls_server_name: "trojan.example.net", acme_email: "ops@example.net" }, "trojan"],
  ["trojan-tls-websocket", { listen_port: 9444, server_address: "trojan-ws.example.net", tls_server_name: "trojan-ws.example.net", acme_email: "ops@example.net", websocket_path: "/trojan", websocket_host: "trojan-ws.example.net" }, "trojan"],
];

describe("production Protocol Profiles", () => {
  it("uses distinct Direct defaults and Cloudflare HTTPS ports for TCP protocols", async () => {
    const types = cases.map(([type]) => type);
    const defaults = await Promise.all(types.map(async (type) => [type, await profileDefaults(type, "system", "direct")] as const));
    const ports = Object.fromEntries(defaults.map(([type, settings]) => [type, settings.listen_port]));
    expect(ports).toEqual({
      "vless-reality-vision": 8443,
      "shadowsocks-aead": 2053,
      "vless-tls-websocket": 443,
      "vless-tls-grpc": 2083,
      hysteria2: 9443,
      tuic: 10443,
      "trojan-tls": 2087,
      "trojan-tls-websocket": 2096,
    });
    expect(new Set(Object.values(ports)).size).toBe(types.length);
  });

  it("generates a Reality public key that matches its private key", async () => {
    const pair = await realityKeypair();
    const privateKey = decodeBase64Url(pair.private_key);
    expect(privateKey[0]! & 7).toBe(0);
    expect(privateKey[31]! & 0xc0).toBe(0x40);
    expect(decodeBase64Url(pair.public_key)).toEqual(x25519.getPublicKey(privateKey));
  });

  it.each(cases)("parses and compiles %s", (type, settings, inboundType) => {
    const parsed = parseProfileSettings(type, settings);
    const inbound = (compileServerConfig(type, parsed, [client]).inbounds as Record<string, unknown>[])[0];
    expect(inbound).toMatchObject({ type: inboundType, listen_port: settings.listen_port });
  });

  it("keeps security-sensitive fixed choices", () => {
    const ss = (compileServerConfig("shadowsocks-aead", cases[1][1], [client]).inbounds as Record<string, unknown>[])[0];
    expect(ss).not.toHaveProperty("network");
    expect(ss).toMatchObject({ multiplex: { enabled: true } });
    const tuic = (compileServerConfig("tuic", cases[5][1], [client]).inbounds as Record<string, unknown>[])[0];
    expect(tuic).toMatchObject({ congestion_control: "bbr", zero_rtt_handshake: false, tls: { alpn: ["h3"] } });
    const grpc = (compileServerConfig("vless-tls-grpc", cases[3][1], [client]).inbounds as Record<string, unknown>[])[0];
    expect(grpc).toMatchObject({ tls: {
      alpn: ["h2"],
      certificate_path: "/etc/nodemanage/certificates/grpc.example.net/current/fullchain.pem",
      key_path: "/etc/nodemanage/certificates/grpc.example.net/current/privatekey.pem",
    }, transport: { type: "grpc", service_name: "NodeManage" } });
    expect(grpc.tls).not.toHaveProperty("acme");
  });

  it("rejects invalid ports and short IDs", () => {
    expect(() => parseProfileSettings("shadowsocks-aead", { ...cases[1][1], listen_port: 70000 })).toThrow("valid port");
    expect(() => parseProfileSettings("vless-reality-vision", { ...cases[0][1], reality_short_id: "not-hex" })).toThrow("hexadecimal");
    expect(() => parseProfileSettings("vless-tls-websocket", { ...cases[2][1], tls_server_name: "https://bad.example.net" })).toThrow("domain name");
    expect(() => parseProfileSettings("vless-tls-websocket", { ...cases[2][1], websocket_path: "missing-slash" })).toThrow("start with /");
  });

  it("uses one Reality target as both handshake host and SNI", () => {
    const parsed = parseProfileSettings("vless-reality-vision", {
      ...cases[0][1],
      server_name: "mismatched.example.com",
      reality_handshake_server: "www.cloudflare.com",
    });
    expect(parsed.server_name).toBe("www.cloudflare.com");
    expect(parsed.reality_handshake_server).toBe("www.cloudflare.com");
  });
});

describe("subscriptions", () => {
  it.each(cases)("generates sing-box, Mihomo and URI for %s", (type, settings, protocol) => {
    const node = { id: `node-${type}`, name: "Tokyo", connect_host: "node.example.com", connect_port: settings.listen_port, ingress_mode: "direct" as const, type, settings_json: JSON.stringify(settings) };
    const singBox = JSON.parse(singBoxSubscription(client, [node])) as {
      dns: { servers: Array<{ type: string; tag: string; server: string }> };
      inbounds: Array<{ type: string; address: string[]; auto_route: boolean; strict_route: boolean }>;
      outbounds: Array<{ type: string; tag: string; outbounds?: string[]; default?: string }>;
      route: { final: string; default_domain_resolver: string; auto_detect_interface: boolean; rules: Array<Record<string, unknown>> };
    };
    expect(singBox.outbounds[0]?.type).toBe(protocol);
    expect(singBox.outbounds[1]).toMatchObject({ type: "selector", tag: "节点选择", outbounds: [`Tokyo · ${type}`], default: `Tokyo · ${type}` });
    expect(singBox.outbounds[2]).toEqual({ type: "direct", tag: "direct" });
    expect(singBox.inbounds).toEqual([{ type: "tun", tag: "tun-in", address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], auto_route: true, strict_route: true }]);
    expect(singBox.dns.servers).toEqual([
      { type: "tls", tag: "proxy-dns", server: "8.8.8.8" },
      { type: "udp", tag: "local-dns", server: "223.5.5.5" },
    ]);
    expect(singBox.route).toMatchObject({
      final: "节点选择",
      default_domain_resolver: "local-dns",
      auto_detect_interface: true,
      rules: [
        { action: "sniff" },
        { protocol: "dns", action: "hijack-dns" },
        { ip_is_private: true, action: "route", outbound: "direct" },
      ],
    });
    expect(mihomoSubscription(client, [node])).toContain("proxies:");
    expect(uriSubscription(client, [node])).toContain(settings.server_address ?? "node.example.com");
  });

  it("keeps an empty sing-box subscription valid when no healthy nodes are available", () => {
    expect(JSON.parse(singBoxSubscription(client, []))).toEqual({ outbounds: [] });
  });

  it("does not enable unsupported uTLS for QUIC outbounds", () => {
    for (const [type, settings] of [cases[4], cases[5]]) {
      const node = { id: `node-${type}`, name: "Tokyo", connect_host: "node.example.com", connect_port: settings.listen_port, ingress_mode: "direct" as const, type, settings_json: JSON.stringify(settings) };
      const outbound = JSON.parse(singBoxSubscription(client, [node])).outbounds[0] as { tls: Record<string, unknown> };
      expect(outbound.tls).not.toHaveProperty("utls");
    }
  });

  it("emits cross-core TUIC compatibility parameters", () => {
    const node = { id: "node-tuic", name: "Tokyo", connect_host: "tuic.example.net", connect_port: 10443, ingress_mode: "direct" as const, type: "tuic" as const, settings_json: JSON.stringify(cases[5][1]) };
    const outbound = JSON.parse(singBoxSubscription(client, [node])).outbounds[0] as { heartbeat: string; tls: { alpn: string[] } };
    expect(outbound).toMatchObject({ heartbeat: "10s", tls: { alpn: ["h3"] } });
    const mihomo = mihomoSubscription(client, [node]);
    expect(mihomo).toContain("    alpn:\n      - h3");
    expect(mihomo).toContain("    heartbeat-interval: 10000");
    expect(mihomo).toContain("    request-timeout: 8000");
    expect(mihomo).toContain("    reduce-rtt: false");
    const uri = uriSubscription(client, [node]);
    expect(uri).toContain("alpn=h3");
    expect(uri).toContain("zero_rtt_handshake=0");
  });

  it("derives the Reality subscription public key from the server private key", async () => {
    const pair = await realityKeypair();
    const settings = { ...cases[0][1], reality_private_key: pair.private_key, reality_public_key: "mismatched-public-key" };
    const node = { id: "node-reality", name: "Tokyo", connect_host: "node.example.com", connect_port: 443, ingress_mode: "direct" as const, type: "vless-reality-vision" as const, settings_json: JSON.stringify(settings) };
    const outbound = JSON.parse(singBoxSubscription(client, [node])).outbounds[0] as { tls: { reality: { public_key: string } } };
    expect(outbound.tls.reality.public_key).toBe(pair.public_key);
    expect(uriSubscription(client, [node])).toContain(`pbk=${encodeURIComponent(pair.public_key)}`);
  });

  it("encodes every URI node as one standard v2rayN subscription", () => {
    const nodes = ["Tokyo", "Osaka"].map((name, index) => ({
      id: `node-${index}`,
      name,
      connect_host: `${name.toLowerCase()}.example.com`,
      connect_port: 443,
      ingress_mode: "direct" as const,
      type: "vless-reality-vision" as const,
      settings_json: JSON.stringify(cases[0][1]),
    }));
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(v2rayNSubscription(client, nodes)), (character) => character.charCodeAt(0)));
    expect(decoded.trim().split("\n")).toHaveLength(2);
    expect(decoded).toContain("Tokyo");
    expect(decoded).toContain("Osaka");
  });

  it("emits a SIP008 Shadowsocks subscription containing only Shadowsocks nodes", () => {
    const shadowsocksNode = { id: "11111111-2222-4333-8444-555555555555", name: "Tokyo", connect_host: "ss.example.com", connect_port: 8388, ingress_mode: "direct" as const, type: "shadowsocks-aead" as const, settings_json: JSON.stringify(cases[1][1]) };
    const vlessNode = { id: "66666666-7777-4888-8999-000000000000", name: "Osaka", connect_host: "vless.example.com", connect_port: 443, ingress_mode: "direct" as const, type: "vless-reality-vision" as const, settings_json: JSON.stringify(cases[0][1]) };
    expect(JSON.parse(shadowsocksSubscription(client, [shadowsocksNode, vlessNode]))).toEqual({
      version: 1,
      servers: [{
        id: shadowsocksNode.id,
        remarks: "Tokyo · shadowsocks-aead",
        server: "ss.example.com",
        server_port: 8388,
        password: `${cases[1][1].shadowsocks_server_password}:${client.shadowsocks_password}`,
        method: cases[1][1].shadowsocks_method,
      }],
    });
  });
});

describe("multiple protocols on one VPS", () => {
  it("compiles every selected protocol and expands them in subscriptions", () => {
    const profiles = cases.map(([type, settings]) => ({ type, settings }));
    expect((compileServerProfiles(profiles, [client]).inbounds as unknown[])).toHaveLength(8);
    const node = { id: "multi", name: "Tokyo", connect_host: "node.example.com", connect_port: 443, ingress_mode: "direct" as const, type: profiles[0].type, settings_json: JSON.stringify(profiles[0].settings), protocols_json: JSON.stringify(profiles) };
    const singBoxOutbounds = JSON.parse(singBoxSubscription(client, [node])).outbounds as Array<{ type: string; outbounds?: string[] }>;
    expect(singBoxOutbounds).toHaveLength(10);
    expect(singBoxOutbounds[8]).toMatchObject({ type: "selector", outbounds: expect.arrayContaining(profiles.map(({ type }) => `Tokyo · ${type}`)) });
    expect(singBoxOutbounds[9]).toEqual({ type: "direct", tag: "direct" });
    expect(uriSubscription(client, [node]).trim().split("\n")).toHaveLength(8);
  });

  it("shares one managed certificate between TLS protocols on the same domain", () => {
    const shared = [
      { type: "vless-tls-websocket" as const, settings: { ...cases[2][1], tls_server_name: "shared.example.net", acme_email: "ops@example.net" } },
      { type: "trojan-tls-websocket" as const, settings: { ...cases[7][1], tls_server_name: "shared.example.net", acme_email: "ops@example.net" } },
    ];
    expect(certificateRequirements(shared, "direct")).toEqual([{ domain: "shared.example.net", email: "ops@example.net" }]);
    const inbounds = compileServerProfiles(shared, [client]).inbounds as Array<{ tls: { certificate_path: string } }>;
    expect(inbounds[0]?.tls.certificate_path).toBe(inbounds[1]?.tls.certificate_path);
    expect(() => certificateRequirements([
      shared[0],
      { ...shared[1], settings: { ...shared[1].settings, acme_email: "security@example.net" } },
    ], "direct")).toThrow("相同的 ACME 邮箱");
    expect(certificateRequirements(shared, "cloudflare_tunnel")).toEqual([]);
  });

  it("terminates TLS at Cloudflare and publishes the verified hostname", () => {
    const settings = parseProfileSettings("vless-tls-websocket", { listen_port: 18081, edge_port: 443, websocket_path: "/proxy" }, "cloudflare_tunnel");
    const inbound = (compileServerConfig("vless-tls-websocket", settings, [client], "cloudflare_tunnel").inbounds as Record<string, unknown>[])[0];
    expect(inbound).toMatchObject({ listen: "127.0.0.1", listen_port: 18081, transport: { type: "ws", path: "/proxy" } });
    expect(inbound).not.toHaveProperty("tls");
    const node = { id: "tunnel", name: "Tunnel", connect_host: "random.trycloudflare.com", connect_port: 443, ingress_mode: "cloudflare_tunnel" as const, type: "vless-tls-websocket" as const, settings_json: JSON.stringify(settings) };
    expect(uriSubscription(client, [node])).toContain("random.trycloudflare.com:443");
  });

  it("supports both public WebSocket protocols and only documented HTTPS edge ports", () => {
    const settings = parseProfileSettings("trojan-tls-websocket", { listen_port: 18082, edge_port: 8443, websocket_path: "/trojan" }, "cloudflare_tunnel");
    const inbound = (compileServerConfig("trojan-tls-websocket", settings, [client], "cloudflare_tunnel").inbounds as Record<string, unknown>[])[0];
    expect(inbound).toMatchObject({ type: "trojan", listen: "127.0.0.1", listen_port: 18082, transport: { type: "ws", path: "/trojan" } });
    expect(inbound).not.toHaveProperty("tls");
    expect(tunnelEdgePort("quick", 443)).toBe(443);
    expect(tunnelEdgePort("named", 8443)).toBe(8443);
    expect(() => tunnelEdgePort("quick", 8443)).toThrow("不支持");
    expect(() => tunnelEdgePort("named", 9443)).toThrow("不支持");
    expect(ingressCapabilities()).toMatchObject({ cloudflare_tunnel: { quick: { protocols: ["vless-tls-websocket", "trojan-tls-websocket"], edge_ports: [443], multiple_protocols: false }, named: { edge_ports: [443, 2053, 2083, 2087, 2096, 8443], multiple_protocols: true } } });
    const vless = parseProfileSettings("vless-tls-websocket", { listen_port: 18081, edge_port: 443, websocket_path: "/vless" }, "cloudflare_tunnel");
    const node = { id: "named-dual", name: "Named", connect_host: "tunnel.example.com", connect_port: 443, ingress_mode: "cloudflare_tunnel" as const, type: "vless-tls-websocket" as const, settings_json: JSON.stringify(vless), protocols_json: JSON.stringify([{ type: "vless-tls-websocket", settings: vless }, { type: "trojan-tls-websocket", settings }]) };
    const links = uriSubscription(client, [node]);
    expect(links).toContain("tunnel.example.com:443");
    expect(links).toContain("tunnel.example.com:8443");
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

  it("accepts six-character passwords and rejects shorter configuration", async () => {
    const sixCharacterEnv = { ADMIN_PASSWORD: "abc123", LOGIN_RATE_LIMITER: allow };
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "abc123" }),
    }), sixCharacterEnv)).resolves.toMatchObject({ status: 200 });
    await expect(handleAdminAuth(new Request("https://manage.example.com/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "abc12" }),
    }), { ADMIN_PASSWORD: "abc12", LOGIN_RATE_LIMITER: allow })).rejects.toThrow("at least 6 characters");
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
