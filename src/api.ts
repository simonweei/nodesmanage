import { requireAdmin, requireAgent } from "./auth";
import { randomBase64, randomToken, randomUuid, sha256Hex } from "./crypto";
import { compileServerConfig, parseProfileSettings, parseProfileType, profileDefaults, type ClientRecord, type NodeRecord, type ProfileType } from "./domain";
import { booleanField, HttpError, json, numberField, readJsonObject, stringField } from "./http";
import { mihomoSubscription, singBoxSubscription, uriSubscription } from "./subscriptions";

interface ProfileRow {
  id: string;
  name: string;
  type: ProfileType;
  settings_json: string;
}

function routeParam(path: string, pattern: RegExp): string | null {
  return pattern.exec(path)?.[1] ?? null;
}

async function listAdmin(env: Env): Promise<Response> {
  const [agents, profiles, nodes, clients, codes, subscriptions] = await Promise.all([
    env.DB.prepare("SELECT id,name,hostname,architecture,os,agent_version,singbox_version,public_ip,current_revision,desired_revision,singbox_running,uptime_seconds,memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,permissions_json,last_error,last_seen,created_at FROM agents ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT id,name,type,settings_json,created_at,updated_at FROM profiles ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT id,agent_id,profile_id,name,address,enabled,created_at,updated_at FROM nodes ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT id,name,uuid,enabled,created_at FROM clients ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT id,name,enabled,max_uses,use_count,created_at FROM enrollment_codes ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT s.id,s.name,s.client_id,s.enabled,s.created_at,c.name AS client_name FROM subscriptions s JOIN clients c ON c.id=s.client_id ORDER BY s.created_at DESC").all(),
  ]);
  return json({ agents: agents.results, profiles: profiles.results, nodes: nodes.results, clients: clients.results, enrollment_codes: codes.results, subscriptions: subscriptions.results });
}

async function createEnrollmentCode(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const code = randomToken(18);
  const name = stringField(body, "name", { required: true, max: 100 });
  const maxUses = numberField(body, "max_uses", { min: 1, max: 1_000_000, integer: true });
  await env.DB.prepare("INSERT INTO enrollment_codes(id,name,code_hash,max_uses) VALUES(?,?,?,?)")
    .bind(id, name, await sha256Hex(code), maxUses)
    .run();
  return json({ id, code, name, max_uses: maxUses }, { status: 201 });
}

async function createProfile(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const type = parseProfileType(body.type);
  const submitted = body.settings && typeof body.settings === "object" && !Array.isArray(body.settings) ? body.settings as Record<string, unknown> : {};
  const settings = parseProfileSettings(type, { ...(await profileDefaults(type)), ...submitted });
  await env.DB.prepare("INSERT INTO profiles(id,name,type,settings_json) VALUES(?,?,?,?)")
    .bind(id, name, type, JSON.stringify(settings))
    .run();
  return json({ id, name, type, settings }, { status: 201 });
}

async function createClient(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const uuid = randomUuid();
  await env.DB.prepare("INSERT INTO clients(id,name,uuid,hysteria2_password,trojan_password,tuic_password,shadowsocks_password) VALUES(?,?,?,?,?,?,?)")
    .bind(id, name, uuid, randomToken(24), randomToken(24), randomToken(24), randomBase64(16)).run();
  return json({ id, name, uuid }, { status: 201 });
}

async function createSubscription(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const clientId = stringField(body, "client_id", { required: true, max: 64 });
  const client = await env.DB.prepare("SELECT id FROM clients WHERE id=? AND enabled=1").bind(clientId).first();
  if (!client) throw new HttpError(404, "client not found");
  const token = randomToken();
  await env.DB.prepare("INSERT INTO subscriptions(id,name,client_id,token_hash) VALUES(?,?,?,?)")
    .bind(id, name, clientId, await sha256Hex(token))
    .run();
  return json({ id, name, client_id: clientId, token }, { status: 201 });
}

async function bindNode(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const agentId = stringField(body, "agent_id", { required: true, max: 64 });
  const profileId = stringField(body, "profile_id", { required: true, max: 64 });
  const name = stringField(body, "name", { required: true, max: 100 });
  const address = stringField(body, "address", { required: true, max: 253 });
  await env.DB.prepare(`INSERT INTO nodes(id,agent_id,profile_id,name,address) VALUES(?,?,?,?,?)
    ON CONFLICT(agent_id) DO UPDATE SET profile_id=excluded.profile_id,name=excluded.name,address=excluded.address,enabled=1,updated_at=CURRENT_TIMESTAMP`)
    .bind(id, agentId, profileId, name, address)
    .run();
  return json({ id, agent_id: agentId, profile_id: profileId, name, address }, { status: 201 });
}

async function publishAgent(agentId: string, env: Env): Promise<Response> {
  const profile = await env.DB.prepare(`SELECT p.id,p.name,p.type,p.settings_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.agent_id=? AND n.enabled=1`)
    .bind(agentId)
    .first<ProfileRow>();
  if (!profile) throw new HttpError(404, "enabled node/profile not found");
  const clients = await env.DB.prepare("SELECT id,name,uuid,hysteria2_password,trojan_password,tuic_password,shadowsocks_password FROM clients WHERE enabled=1 ORDER BY created_at").all<ClientRecord>();
  if (clients.results.length === 0) throw new HttpError(409, "create at least one enabled client first");
  const settings = parseProfileSettings(profile.type, JSON.parse(profile.settings_json) as unknown);
  const configJson = JSON.stringify(compileServerConfig(profile.type, settings, clients.results), null, 2);
  const digest = await sha256Hex(configJson);
  const insert = await env.DB.prepare("INSERT INTO revisions(agent_id,profile_id,config_json,sha256) VALUES(?,?,?,?)")
    .bind(agentId, profile.id, configJson, digest)
    .run();
  const revision = Number(insert.meta.last_row_id);
  await env.DB.prepare("UPDATE agents SET desired_revision=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(revision, agentId).run();
  return json({ agent_id: agentId, desired_revision: revision, sha256: digest }, { status: 201 });
}

async function rollbackAgent(agentId: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const revision = numberField(body, "revision", { min: 1, integer: true });
  if (revision === null) throw new HttpError(400, "revision is required");
  const found = await env.DB.prepare("SELECT id FROM revisions WHERE id=? AND agent_id=?").bind(revision, agentId).first();
  if (!found) throw new HttpError(404, "revision not found for agent");
  await env.DB.prepare("UPDATE agents SET desired_revision=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(revision, agentId).run();
  return json({ agent_id: agentId, desired_revision: revision });
}

async function registerAgent(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const code = stringField(body, "code", { required: true, max: 256 });
  const name = stringField(body, "name", { required: true, max: 100 });
  const hostname = stringField(body, "hostname", { required: true, max: 253 });
  const architecture = stringField(body, "architecture", { required: true, max: 32 });
  const os = stringField(body, "os", { required: true, max: 64 });
  const codeHash = await sha256Hex(code);
  const use = await env.DB.prepare(`UPDATE enrollment_codes SET use_count=use_count+1
    WHERE code_hash=? AND enabled=1 AND (max_uses IS NULL OR use_count < max_uses) RETURNING id`)
    .bind(codeHash)
    .first<{ id: string }>();
  if (!use) throw new HttpError(401, "invalid or disabled enrollment code");

  const id = randomUuid();
  const token = randomToken();
  await env.DB.prepare("INSERT INTO agents(id,name,hostname,token_hash,architecture,os,public_ip) VALUES(?,?,?,?,?,?,?)")
    .bind(
      id,
      name,
      hostname,
      await sha256Hex(token),
      architecture,
      os,
      request.headers.get("cf-connecting-ip") ?? "",
    )
    .run();
  return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60 }, { status: 201 });
}

async function setEnabled(resource: string, id: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const enabled = booleanField(body, "enabled");
  const table = resource === "enrollment-codes" ? "enrollment_codes" : resource === "subscriptions" ? "subscriptions" : resource === "clients" ? "clients" : resource === "nodes" ? "nodes" : null;
  if (!table) throw new HttpError(404, "resource not found");
  const result = await env.DB.prepare(`UPDATE ${table} SET enabled=? WHERE id=?`).bind(enabled ? 1 : 0, id).run();
  if (!result.meta.changes) throw new HttpError(404, "record not found");
  return json({ id, enabled });
}

function boundedPermissions(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "permissions must be an object");
  const encoded = JSON.stringify(value);
  if (encoded.length > 8192) throw new HttpError(400, "permissions is too large");
  return encoded;
}

async function syncAgent(request: Request, env: Env): Promise<Response> {
  const agent = await requireAgent(request, env);
  const body = await readJsonObject(request);
  const reportedRevision = numberField(body, "current_revision", { min: 1, integer: true });
  const permissions = boundedPermissions(body.permissions);
  await env.DB.prepare(`UPDATE agents SET
    agent_version=?,singbox_version=?,public_ip=?,singbox_running=?,uptime_seconds=?,memory_total_bytes=?,memory_used_bytes=?,disk_total_bytes=?,disk_used_bytes=?,permissions_json=?,last_seen=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
    current_revision=CASE WHEN EXISTS(SELECT 1 FROM revisions WHERE id=? AND agent_id=?) THEN ? ELSE current_revision END
    WHERE id=?`)
    .bind(
      stringField(body, "agent_version", { max: 64 }),
      stringField(body, "singbox_version", { max: 128 }),
      request.headers.get("cf-connecting-ip") ?? "",
      booleanField(body, "singbox_running") ? 1 : 0,
      numberField(body, "uptime_seconds", { min: 0, integer: true }),
      numberField(body, "memory_total_bytes", { min: 0, integer: true }),
      numberField(body, "memory_used_bytes", { min: 0, integer: true }),
      numberField(body, "disk_total_bytes", { min: 0, integer: true }),
      numberField(body, "disk_used_bytes", { min: 0, integer: true }),
      permissions,
      reportedRevision,
      agent.id,
      reportedRevision,
      agent.id,
    )
    .run();
  const state = await env.DB.prepare("SELECT current_revision,desired_revision FROM agents WHERE id=?").bind(agent.id).first<{ current_revision: number | null; desired_revision: number | null }>();
  if (!state) throw new HttpError(404, "agent not found");
  if (state.desired_revision && state.desired_revision !== state.current_revision) {
    const revision = await env.DB.prepare("SELECT id,config_json,sha256 FROM revisions WHERE id=? AND agent_id=?")
      .bind(state.desired_revision, agent.id)
      .first<{ id: number; config_json: string; sha256: string }>();
    if (revision) return json({ desired_revision: revision.id, config_json: revision.config_json, sha256: revision.sha256, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60 });
  }
  return json({ desired_revision: state.desired_revision, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60 });
}

async function agentResult(request: Request, env: Env): Promise<Response> {
  const agent = await requireAgent(request, env);
  const body = await readJsonObject(request);
  const revision = numberField(body, "revision", { min: 1, integer: true });
  if (revision === null) throw new HttpError(400, "revision is required");
  const success = booleanField(body, "success");
  const error = stringField(body, "error", { max: 2048 });
  if (success) {
    const result = await env.DB.prepare(`UPDATE agents SET current_revision=?,last_error=NULL,updated_at=CURRENT_TIMESTAMP
      WHERE id=? AND desired_revision=? AND EXISTS(SELECT 1 FROM revisions WHERE id=? AND agent_id=?)`)
      .bind(revision, agent.id, revision, revision, agent.id)
      .run();
    if (!result.meta.changes) throw new HttpError(409, "revision is no longer desired");
  } else {
    await env.DB.prepare("UPDATE agents SET last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(error || "configuration apply failed", agent.id).run();
  }
  return json({ ok: true });
}

async function subscription(path: string, env: Env): Promise<Response> {
  const match = /^\/sub\/([a-f0-9]{64})\/(sing-box|mihomo|uri)$/.exec(path);
  if (!match) throw new HttpError(404, "subscription not found");
  const tokenHash = await sha256Hex(match[1] ?? "");
  const client = await env.DB.prepare(`SELECT c.id,c.name,c.uuid,c.hysteria2_password,c.trojan_password,c.tuic_password,c.shadowsocks_password FROM subscriptions s JOIN clients c ON c.id=s.client_id
    WHERE s.token_hash=? AND s.enabled=1 AND c.enabled=1`).bind(tokenHash).first<ClientRecord>();
  if (!client) throw new HttpError(404, "subscription not found");
  const nodes = await env.DB.prepare(`SELECT n.id,n.name,n.address,p.type,p.settings_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.enabled=1 ORDER BY n.created_at`).all<NodeRecord>();
  const format = match[2];
  const output = format === "sing-box" ? singBoxSubscription(client, nodes.results) : format === "mihomo" ? mihomoSubscription(client, nodes.results) : uriSubscription(client, nodes.results);
  const contentType = format === "mihomo" ? "text/yaml; charset=utf-8" : format === "sing-box" ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
  return new Response(output, { headers: { "content-type": contentType, "cache-control": "private, max-age=60", "subscription-userinfo": "upload=0; download=0; total=0; expire=0" } });
}

export async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path.startsWith("/sub/")) return subscription(path, env);
  if (path === "/api/agent/register" && request.method === "POST") return registerAgent(request, env);
  if (path === "/api/agent/sync" && request.method === "POST") return syncAgent(request, env);
  if (path === "/api/agent/result" && request.method === "POST") return agentResult(request, env);

  await requireAdmin(request, env);
  if (path === "/api/admin/state" && request.method === "GET") return listAdmin(env);
  if (path === "/api/admin/profile-defaults" && request.method === "GET") {
    const type = parseProfileType(url.searchParams.get("type"));
    return json({ type, settings: await profileDefaults(type) });
  }
  if (path === "/api/admin/enrollment-codes" && request.method === "POST") return createEnrollmentCode(request, env);
  if (path === "/api/admin/profiles" && request.method === "POST") return createProfile(request, env);
  if (path === "/api/admin/clients" && request.method === "POST") return createClient(request, env);
  if (path === "/api/admin/subscriptions" && request.method === "POST") return createSubscription(request, env);
  if (path === "/api/admin/nodes" && request.method === "POST") return bindNode(request, env);

  const publishId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/publish$/);
  if (publishId && request.method === "POST") return publishAgent(publishId, env);
  const rollbackId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/rollback$/);
  if (rollbackId && request.method === "POST") return rollbackAgent(rollbackId, request, env);
  const enabledMatch = /^\/api\/admin\/(enrollment-codes|subscriptions|clients|nodes)\/([^/]+)\/enabled$/.exec(path);
  if (enabledMatch && request.method === "POST") return setEnabled(enabledMatch[1] ?? "", enabledMatch[2] ?? "", request, env);
  throw new HttpError(404, "not found");
}
