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
    const rejectedLowPort = await jsonRequest("/api/admin/vps", {
      method: "POST", headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Invalid user VPS", deployment_mode: "user", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 443 } }] }),
    });
    expect(rejectedLowPort.status).toBe(400);
    const created = await jsonRequest("/api/admin/vps", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Tokyo 1", region: "JP", address: "node.example.com", protocols: [{ type: "vless-reality-vision", settings: { listen_port: 443 } }] }),
    });
    expect(created.status).toBe(201);
    const value = await created.json<{ id: string; ticket: string }>();
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

  it("creates subscriptions, automatically publishes and serves only applied healthy nodes", async () => {
    const group = await jsonRequest("/api/admin/subscription-groups", {
      method: "POST",
      headers: { cookie: adminCookie },
      body: JSON.stringify({ name: "Team", node_ids: [nodeId], client_names: ["Alice"] }),
    });
    expect(group.status).toBe(201);
    const groupValue = await group.json<{ members: Array<{ id: string; token: string }>; published: Array<{ revision: number }> }>();
    subscriptionToken = groupValue.members[0]?.token ?? "";
    expect(groupValue.published).toHaveLength(1);
    const revision = groupValue.published[0]?.revision;
    expect(revision).toBeTypeOf("number");

    const beforeApply = await SELF.fetch(`${origin}/sub/${groupValue.members[0]?.token}/sing-box`, { headers: { "cf-connecting-ip": "198.51.100.4" } });
    expect(beforeApply.status).toBe(200);
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
    const config = await active.json<{ outbounds: Array<{ server: string }> }>();
    expect(config.outbounds).toHaveLength(1);
    expect(config.outbounds[0]?.server).toBe("node.example.com");
  });

  it("opens and resolves offline alerts during scheduled maintenance", async () => {
    await testEnv.DB.prepare("UPDATE agents SET last_seen=datetime('now','-10 minutes') WHERE id=?").bind(agentId).run();
    await worker.scheduled(createScheduledController(), testEnv, createExecutionContext());
    expect(await testEnv.DB.prepare("SELECT status FROM alerts WHERE subject_key=?").bind(`agent-offline:${agentId}`).first()).toMatchObject({ status: "open" });

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
