import { applyD1Migrations, createExecutionContext, createScheduledController, env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../src/index";

interface TestEnv extends Env { TEST_MIGRATIONS: D1Migration[] }

const testEnv = env as TestEnv;
const origin = "https://manage.example.com";

async function jsonRequest(path: string, init: RequestInit = {}): Promise<Response> {
  return SELF.fetch(`${origin}${path}`, {
    ...init,
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.10", ...(init.headers ?? {}) },
  });
}

describe("control-plane production flow", () => {
  let adminCookie = "";
  let nodeId = "";
  let ticket = "";
  let agentToken = "";
  let agentId = "";
  let subscriptionToken = "";

  beforeAll(async () => {
    await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
    const login = await jsonRequest("/api/auth/login", { method: "POST", body: JSON.stringify({ password: testEnv.ADMIN_PASSWORD }) });
    expect(login.status).toBe(200);
    adminCookie = (login.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
  });

  it("creates a VPS and binds a ticket to one installer claim", async () => {
    const userDefaults = await jsonRequest("/api/admin/profile-defaults?type=vless-reality-vision&mode=user", { headers: { cookie: adminCookie } });
    expect(await userDefaults.json()).toMatchObject({ deployment_mode: "user", settings: { listen_port: 8443 } });
    const rejectedUserTls = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid user TLS", connect_host: "tls.example.net", acme_email: "ops@example.net", deployment_mode: "user", protocols: [{ type: "trojan-tls", settings: { listen_port: 9443 } }] }),
    });
    expect(rejectedUserTls.status).toBe(400);
    const rejectedLowPort = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid user VPS", deployment_mode: "user", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 443 } }] }),
    });
    expect(rejectedLowPort.status).toBe(400);
    const created = await jsonRequest("/api/admin/vps", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Tokyo 1", region: "JP", connect_host: "node.example.com", ingress_mode: "direct", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 443 } }] }),
    });
    expect(created.status).toBe(201);
    const value = await created.json<{ id: string; ticket: string; deployment_policy: string; deployment_mode: string; system_required: boolean }>();
    expect(value).toMatchObject({ deployment_policy: "auto", deployment_mode: "system", system_required: true });
    nodeId = value.id;
    ticket = value.ticket;

    const registration = {
      ticket,
      claim: "11".repeat(32),
      name: "Tokyo 1",
      hostname: "host-1",
      architecture: "amd64",
      os: "linux",
      distro: "debian",
      distro_version: "13",
      libc: "glibc",
      init_system: "systemd",
      install_mode: "system",
    };
    const wrongMode = await jsonRequest("/api/agent/register", { method: "POST", body: JSON.stringify({ ...registration, install_mode: "user" }) });
    expect(wrongMode.status).toBe(409);
    const registered = await jsonRequest("/api/agent/register", { method: "POST", body: JSON.stringify(registration) });
    expect(registered.status).toBe(201);
    const identity = await registered.json<{ agent_id: string; agent_token: string }>();
    agentId = identity.agent_id;
    agentToken = identity.agent_token;

    const retry = await jsonRequest("/api/agent/register", { method: "POST", body: JSON.stringify(registration) });
    expect(retry.status).toBe(200);
    expect(await retry.json()).toMatchObject({ agent_id: agentId, agent_token: agentToken, idempotent: true });

    const stolen = await jsonRequest("/api/agent/register", { method: "POST", body: JSON.stringify({ ...registration, claim: "22".repeat(32) }) });
    expect(stolen.status).toBe(409);
  });

  it("resolves an auto high-port profile to the installer's user mode", async () => {
    const defaults = await jsonRequest("/api/admin/profile-defaults?type=vless-reality-vision&mode=auto", { headers: { cookie: adminCookie } });
    expect(await defaults.json()).toMatchObject({ deployment_policy: "auto", deployment_mode: "user", settings: { listen_port: 8443 } });
    const created = await jsonRequest("/api/admin/vps", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Auto User", connect_host: "user.example.com", deployment_policy: "auto", ingress_mode: "direct", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 8443 } }] }),
    });
    expect(created.status).toBe(201);
    const value = await created.json<{ id: string; ticket: string; deployment_policy: string; system_required: boolean }>();
    expect(value).toMatchObject({ deployment_policy: "auto", system_required: false });

    const registered = await jsonRequest("/api/agent/register", {
      method: "POST",
      body: JSON.stringify({
        ticket: value.ticket,
        claim: "33".repeat(32),
        name: "Auto User",
        hostname: "host-user",
        architecture: "amd64",
        os: "linux",
        distro: "debian",
        distro_version: "13",
        libc: "glibc",
        init_system: "systemd",
        install_mode: "user",
      }),
    });
    expect(registered.status).toBe(201);
    expect(await testEnv.DB.prepare("SELECT deployment_policy,deployment_mode FROM nodes WHERE id=?").bind(value.id).first()).toMatchObject({ deployment_policy: "auto", deployment_mode: "user" });
    const conflictingRetry = await jsonRequest("/api/agent/register", {
      method: "POST",
      body: JSON.stringify({
        ticket: value.ticket,
        claim: "33".repeat(32),
        name: "Auto User",
        hostname: "host-user",
        architecture: "amd64",
        os: "linux",
        distro: "debian",
        distro_version: "13",
        libc: "glibc",
        init_system: "systemd",
        install_mode: "system",
      }),
    });
    expect(conflictingRetry.status).toBe(409);

    const deleted = await jsonRequest(`/api/admin/vps/${value.id}?force=true`, { method: "DELETE", headers: { cookie: adminCookie } });
    expect(deleted.status).toBe(200);
  });

  it("accepts multiple Direct TLS protocols backed by one shared certificate", async () => {
    const created = await jsonRequest("/api/admin/vps", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Shared TLS", connect_host: "shared.example.net", acme_email: "ops@example.net", deployment_policy: "system", ingress_mode: "direct", protocols: [
        { type: "vless-tls-websocket", settings: { listen_port: 8443, websocket_path: "/vless" } },
        { type: "trojan-tls-websocket", settings: { listen_port: 9443, websocket_path: "/trojan" } },
      ] }),
    });
    expect(created.status).toBe(201);
    const value = await created.json<{ id: string; protocols: Array<{ settings: Record<string, string> }> }>();
    expect(value.protocols.map(({ settings }) => settings)).toEqual([
      expect.objectContaining({ server_address: "shared.example.net", tls_server_name: "shared.example.net", websocket_host: "shared.example.net", acme_email: "ops@example.net" }),
      expect.objectContaining({ server_address: "shared.example.net", tls_server_name: "shared.example.net", websocket_host: "shared.example.net", acme_email: "ops@example.net" }),
    ]);
    expect((await jsonRequest(`/api/admin/vps/${value.id}?force=true`, { method: "DELETE", headers: { cookie: adminCookie } })).status).toBe(200);
  });

  it("exposes Tunnel capabilities and validates protocol and edge-port combinations", async () => {
    const capabilities = await jsonRequest("/api/admin/ingress-capabilities", { headers: { cookie: adminCookie } });
    expect(await capabilities.json()).toMatchObject({
      cloudflare_tunnel: {
        quick: { protocols: ["vless-tls-websocket", "trojan-tls-websocket"], edge_ports: [443] },
        named: { edge_ports: [443, 2053, 2083, 2087, 2096, 8443] },
      },
    });
    const missingNamedHostname = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Missing Named Host", ingress_mode: "cloudflare_tunnel", tunnel_kind: "named", protocols: [{ type: "vless-tls-websocket", settings: { listen_port: 18081, edge_port: 443, websocket_path: "/proxy" } }] }),
    });
    expect(missingNamedHostname.status).toBe(400);
    expect(await missingNamedHostname.json()).toMatchObject({ error: "Named Tunnel 必须填写 Cloudflare Public Hostname" });
    const invalidQuickPort = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid Quick", ingress_mode: "cloudflare_tunnel", tunnel_kind: "quick", protocols: [{ type: "vless-tls-websocket", settings: { listen_port: 18081, edge_port: 8443, websocket_path: "/proxy" } }] }),
    });
    expect(invalidQuickPort.status).toBe(400);
    const invalidQuickMultiple = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid Quick Multiple", ingress_mode: "cloudflare_tunnel", tunnel_kind: "quick", protocols: [
        { type: "vless-tls-websocket", settings: { listen_port: 18081, edge_port: 443, websocket_path: "/vless" } },
        { type: "trojan-tls-websocket", settings: { listen_port: 18082, edge_port: 443, websocket_path: "/trojan" } },
      ] }),
    });
    expect(invalidQuickMultiple.status).toBe(400);
    const invalidTunnelProtocol = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid gRPC", ingress_mode: "cloudflare_tunnel", tunnel_kind: "quick", connect_port: 443, protocols: [{ type: "vless-tls-grpc", settings: { listen_port: 18080 } }] }),
    });
    expect(invalidTunnelProtocol.status).toBe(400);
    const named = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Named Dual WS", connect_host: "tunnel.example.com", ingress_mode: "cloudflare_tunnel", tunnel_kind: "named", origin_port: 18080, protocols: [
        { type: "vless-tls-websocket", settings: { listen_port: 18081, edge_port: 443, websocket_path: "/vless" } },
        { type: "trojan-tls-websocket", settings: { listen_port: 18082, edge_port: 8443, websocket_path: "/trojan" } },
      ] }),
    });
    expect(named.status).toBe(201);
    const value = await named.json<{ id: string; connect_port: number; origin_port: number }>();
    expect(value).toMatchObject({ connect_port: 443, origin_port: 18080 });
    expect((await jsonRequest(`/api/admin/vps/${value.id}?force=true`, { method: "DELETE", headers: { cookie: adminCookie } })).status).toBe(200);
  });

  it("creates subscriptions, automatically publishes and serves only applied healthy nodes", async () => {
    const pendingVps = await jsonRequest("/api/admin/vps", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Pending install", connect_host: "pending.example.com", ingress_mode: "direct", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 443 } }] }),
    });
    expect(pendingVps.status).toBe(201);
    const pendingVpsId = (await pendingVps.json<{ id: string }>()).id;
    const pendingOnlyGroup = await jsonRequest("/api/admin/subscription-groups", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Pending only", node_ids: [pendingVpsId] }),
    });
    expect(pendingOnlyGroup.status).toBe(201);
    const pendingOnlyGroupValue = await pendingOnlyGroup.json<{ id: string; published: unknown[] }>();
    expect(pendingOnlyGroupValue.published).toHaveLength(0);
    expect((await jsonRequest(`/api/admin/subscription-groups/${pendingOnlyGroupValue.id}`, { method: "DELETE", headers: { cookie: adminCookie } })).status).toBe(200);
    const group = await jsonRequest("/api/admin/subscription-groups", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Team", node_ids: [nodeId, pendingVpsId], client_names: ["Alice"] }),
    });
    expect(group.status).toBe(201);
    const groupValue = await group.json<{ id: string; members: Array<{ id: string; token: string }>; published: Array<{ revision: number }> }>();
    subscriptionToken = groupValue.members[0]?.token ?? "";
    expect(groupValue.published).toHaveLength(1);
    const revision = groupValue.published[0]?.revision;
    expect(revision).toBeTypeOf("number");

    const beforeApply = await SELF.fetch(`${origin}/sub/${groupValue.members[0]?.token}/sing-box`, { headers: { "cf-connecting-ip": "198.51.100.4" } });
    expect(beforeApply.status).toBe(200);
    expect(beforeApply.headers.get("content-disposition")).toBe("attachment; filename*=UTF-8''Team");
    expect((await beforeApply.json<{ outbounds: unknown[] }>()).outbounds).toHaveLength(0);

    const sync = await jsonRequest("/api/agent/sync", {
      method: "POST",
      headers: { authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ current_revision: null, permissions: {}, agent_version: "0.5.0", singbox_version: "1.13.12", singbox_running: true }),
    });
    expect(sync.status).toBe(200);
    expect(await sync.json()).toMatchObject({ desired_revision: revision });

    const applied = await jsonRequest("/api/agent/result", {
      method: "POST",
      headers: { authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ revision, success: true }),
    });
    expect(applied.status).toBe(200);

    const active = await SELF.fetch(`${origin}/sub/${groupValue.members[0]?.token}/sing-box`, { headers: { "cf-connecting-ip": "198.51.100.4" } });
    expect(active.status).toBe(200);
    const config = await active.json<{ dns: { servers: Array<{ type: string; tag: string }>; rules: Array<{ server: string }> }; inbounds: Array<{ type: string; auto_route: boolean }>; outbounds: Array<{ type: string; tag: string; server?: string; outbounds?: string[] }>; route: { final: string; default_domain_resolver: string } }>();
    expect(config.outbounds).toHaveLength(3);
    expect(config.outbounds[0]?.server).toBe("node.example.com");
    expect(config.outbounds[1]).toMatchObject({ type: "selector", tag: "节点选择", outbounds: ["Tokyo 1 · vless-reality-vision"] });
    expect(config.outbounds[2]).toEqual({ type: "direct", tag: "direct" });
    expect(config.inbounds).toContainEqual(expect.objectContaining({ type: "tun", auto_route: true }));
    expect(config.route).toMatchObject({ final: "节点选择", default_domain_resolver: "local-dns" });
    expect(config.dns.servers).toContainEqual(expect.objectContaining({ type: "fakeip", tag: "fakeip-dns" }));
    expect(config.dns.rules).toContainEqual(expect.objectContaining({ server: "fakeip-dns" }));

    const shadowsocks = await SELF.fetch(`${origin}/sub/${groupValue.members[0]?.token}/shadowsocks`, { headers: { "cf-connecting-ip": "198.51.100.4" } });
    expect(shadowsocks.status).toBe(200);
    expect(shadowsocks.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await shadowsocks.json()).toEqual({ version: 1, servers: [] });

    expect((await jsonRequest(`/api/admin/vps/${pendingVpsId}?force=true`, { method: "DELETE", headers: { cookie: adminCookie } })).status).toBe(200);
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM subscription_group_nodes WHERE group_id=? AND node_id=?").bind(groupValue.id, pendingVpsId).first()).toMatchObject({ count: 0 });
  });

  it("opens and resolves offline alerts during scheduled maintenance", async () => {
    await testEnv.DB.prepare("UPDATE agents SET last_seen=datetime('now','-10 minutes') WHERE id=?").bind(agentId).run();
    await worker.scheduled(createScheduledController(), testEnv, createExecutionContext());
    expect(await testEnv.DB.prepare("SELECT status FROM alerts WHERE subject_key=?").bind(`agent-offline:${agentId}`).first()).toMatchObject({ status: "open" });

    const state = await jsonRequest("/api/admin/state", { headers: { cookie: adminCookie } });
    const stateValue = await state.json<{ alerts: Array<{ kind: string; node_id: string }> }>();
    expect(stateValue.alerts).toContainEqual(expect.objectContaining({ kind: "agent_offline", node_id: nodeId }));

    await testEnv.DB.prepare("UPDATE agents SET last_seen=CURRENT_TIMESTAMP WHERE id=?").bind(agentId).run();
    await worker.scheduled(createScheduledController(), testEnv, createExecutionContext());
    expect(await testEnv.DB.prepare("SELECT status FROM alerts WHERE subject_key=?").bind(`agent-offline:${agentId}`).first()).toMatchObject({ status: "resolved" });
  });

  it("retires with an empty revision before revoking the Agent", async () => {
    const retirement = await jsonRequest(`/api/admin/vps/${nodeId}`, { method: "DELETE", headers: { cookie: adminCookie } });
    expect(retirement.status).toBe(202);
    const retirementValue = await retirement.json<{ published: Array<{ revision: number }> }>();
    const revision = retirementValue.published[0]?.revision;

    const sync = await jsonRequest("/api/agent/sync", {
      method: "POST",
      headers: { authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ current_revision: null, permissions: {}, agent_version: "0.4.0", singbox_version: "1.13.12", singbox_running: true }),
    });
    const desired = await sync.json<{ config_json: string }>();
    expect(JSON.parse(desired.config_json).inbounds[0].users).toHaveLength(0);

    await jsonRequest("/api/agent/result", {
      method: "POST",
      headers: { authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ revision, success: true }),
    });
    const deleted = await jsonRequest(`/api/admin/vps/${nodeId}`, { method: "DELETE", headers: { cookie: adminCookie } });
    expect(deleted.status).toBe(200);
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM agents").first()).toMatchObject({ count: 0 });
    expect(await testEnv.DB.prepare("SELECT COUNT(*) AS count FROM nodes").first()).toMatchObject({ count: 0 });

    const empty = await SELF.fetch(`${origin}/sub/${subscriptionToken}/sing-box`, { headers: { "cf-connecting-ip": "198.51.100.4" } });
    expect(empty.status).toBe(200);
    expect((await empty.json<{ outbounds: unknown[] }>()).outbounds).toHaveLength(0);
  });
});
