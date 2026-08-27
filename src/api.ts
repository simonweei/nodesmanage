import { requireAdmin, requireAgent } from "./auth";
import { hmacHex, randomBase64, randomToken, randomUuid, sha256Hex } from "./crypto";
import { compileServerProfiles, parseProfileSettings, parseProfileType, profileDefaults, type ClientRecord, type NodeRecord, type ProfileType, type ProtocolProfile } from "./domain";
import { booleanField, HttpError, json, numberField, readJsonObject, stringField } from "./http";
import { mihomoSubscription, singBoxSubscription, uriSubscription } from "./subscriptions";

interface ProfileRow {
  id: string;
  name: string;
  type: ProfileType;
  settings_json: string;
  protocols_json?: string | null;
}

function routeParam(path: string, pattern: RegExp): string | null {
  return pattern.exec(path)?.[1] ?? null;
}

async function listAdmin(env: Env): Promise<Response> {
  const [agents, profiles, nodes, clients, subscriptions, groups, groupNodes, installEvents] = await Promise.all([
    env.DB.prepare("SELECT id,name,hostname,os,distro,distro_version,architecture,libc,init_system,install_mode,agent_version,singbox_version,public_ip,current_revision,desired_revision,singbox_running,cpu_usage_percent,uptime_seconds,memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,permissions_json,last_error,last_seen,created_at FROM agents ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT id,name,type,settings_json,protocols_json,created_at,updated_at FROM profiles ORDER BY created_at DESC").all(),
    env.DB.prepare(`SELECT n.id,n.agent_id,n.profile_id,n.name,n.region,
      COALESCE(NULLIF(n.address,''),a.public_ip,'') AS address,n.address AS configured_address,n.enabled,n.draft,n.install_stage,n.last_install_error_code,n.last_install_message,n.last_install_source,n.last_install_at,n.created_at,n.updated_at,
      p.type,p.settings_json,p.protocols_json,a.hostname,a.os,a.distro,a.distro_version,a.architecture,a.libc,a.init_system,a.install_mode,a.agent_version,a.singbox_version,a.public_ip,
      a.current_revision,a.desired_revision,a.singbox_running,a.cpu_usage_percent,a.uptime_seconds,a.memory_total_bytes,a.memory_used_bytes,
      a.disk_total_bytes,a.disk_used_bytes,a.permissions_json,a.last_error,a.last_seen
      FROM nodes n JOIN profiles p ON p.id=n.profile_id LEFT JOIN agents a ON a.id=n.agent_id ORDER BY n.created_at DESC`).all(),
    env.DB.prepare("SELECT id,name,uuid,enabled,created_at FROM clients ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT s.id,s.name,s.group_id,s.client_id,s.enabled,s.created_at,c.name AS client_name FROM subscriptions s JOIN clients c ON c.id=s.client_id ORDER BY s.created_at DESC").all(),
    env.DB.prepare("SELECT id,name,enabled,created_at,updated_at FROM subscription_groups ORDER BY created_at DESC").all(),
    env.DB.prepare("SELECT group_id,node_id FROM subscription_group_nodes").all(),
    env.DB.prepare("SELECT id,node_id,stage,error_code,message,source,created_at FROM install_events ORDER BY id DESC LIMIT 500").all(),
  ]);
  const subscriptionGroups = groups.results.map((group) => ({
    ...group,
    nodes: groupNodes.results.filter((item) => item.group_id === group.id).map((item) => item.node_id),
    clients: subscriptions.results.filter((item) => item.group_id === group.id).map((item) => ({ id: item.client_id, name: item.client_name, subscription_id: item.id, enabled: item.enabled })),
  }));
  return json({ agents: agents.results, profiles: profiles.results, vps: nodes.results, nodes: nodes.results, clients: clients.results, subscriptions: subscriptions.results, subscription_groups: subscriptionGroups, install_events: installEvents.results });
}

function stringArray(value: unknown, name: string, max = 100): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) throw new HttpError(400, `${name} must be a non-empty array`);
  const result = value.map((item) => {
    if (typeof item !== "string" || !item.trim() || item.length > 100) throw new HttpError(400, `${name} contains an invalid value`);
    return item.trim();
  });
  return [...new Set(result)];
}

function submittedSettings(body: Record<string, unknown>): Record<string, unknown> {
  return body.settings && typeof body.settings === "object" && !Array.isArray(body.settings) ? body.settings as Record<string, unknown> : {};
}

async function submittedProtocols(body: Record<string, unknown>): Promise<ProtocolProfile[]> {
  if (!Array.isArray(body.protocols) || body.protocols.length === 0 || body.protocols.length > 8) {
    throw new HttpError(400, "protocols must be a non-empty array");
  }
  const types = new Set<ProfileType>();
  const profiles: ProtocolProfile[] = [];
  for (const item of body.protocols) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(400, "protocol is invalid");
    const value = item as Record<string, unknown>;
    const type = parseProfileType(value.type);
    if (types.has(type)) throw new HttpError(400, "protocols cannot contain duplicates");
    types.add(type);
    const submitted = value.settings && typeof value.settings === "object" && !Array.isArray(value.settings) ? value.settings as Record<string, unknown> : {};
    profiles.push({ type, settings: parseProfileSettings(type, { ...(await profileDefaults(type)), ...submitted }) });
  }
  const ports = new Set<number>();
  for (const profile of profiles) {
    if (ports.has(profile.settings.listen_port)) throw new HttpError(400, "每个协议必须使用不同的监听端口");
    ports.add(profile.settings.listen_port);
  }
  return profiles;
}

function storedProtocols(profile: ProfileRow): ProtocolProfile[] {
  if (profile.protocols_json) return JSON.parse(profile.protocols_json) as ProtocolProfile[];
  return [{ type: profile.type, settings: JSON.parse(profile.settings_json) as ProtocolProfile["settings"] }];
}

async function freshInstallTicket(nodeId: string, env: Env): Promise<{ id: string; ticket: string }> {
  const id = randomUuid();
  const ticket = randomToken(24);
  await env.DB.batch([
    env.DB.prepare("UPDATE install_tickets SET used_at=CURRENT_TIMESTAMP WHERE node_id=? AND used_at IS NULL").bind(nodeId),
    env.DB.prepare("UPDATE nodes SET install_stage='ticket_created',last_install_error_code=NULL,last_install_message='',last_install_source='',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(nodeId),
    env.DB.prepare("INSERT INTO install_tickets(id,node_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+15 minutes'))").bind(id, nodeId, await sha256Hex(ticket)),
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) VALUES(?,'ticket_created','Install ticket created','worker')").bind(nodeId),
  ]);
  return { id, ticket };
}

async function createVps(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const profileId = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const region = stringField(body, "region", { max: 100 });
  const address = stringField(body, "address", { max: 253 });
  const protocols = body.protocols ? await submittedProtocols(body) : [{ type: parseProfileType(body.type), settings: parseProfileSettings(parseProfileType(body.type), { ...(await profileDefaults(parseProfileType(body.type))), ...submittedSettings(body) }) }];
  const { type, settings } = protocols[0]!;
  const installTicketId = randomUuid();
  const ticket = randomToken(24);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO profiles(id,name,type,settings_json,protocols_json) VALUES(?,?,?,?,?)").bind(profileId, name, type, JSON.stringify(settings), JSON.stringify(protocols)),
    env.DB.prepare("INSERT INTO nodes(id,profile_id,name,region,address,draft) VALUES(?,?,?,?,?,1)").bind(id, profileId, name, region, address),
    env.DB.prepare("INSERT INTO install_tickets(id,node_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+15 minutes'))").bind(installTicketId, id, await sha256Hex(ticket)),
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) VALUES(?,'ticket_created','Install ticket created','worker')").bind(id),
  ]);
  return json({ id, name, region, address, type, settings, protocols, ticket, expires_in_seconds: 900 }, { status: 201 });
}

async function updateVps(id: string, request: Request, env: Env): Promise<Response> {
  const current = await env.DB.prepare("SELECT n.profile_id,n.name,p.type,p.settings_json,p.protocols_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.id=?").bind(id).first<ProfileRow & { profile_id: string }>();
  if (!current) throw new HttpError(404, "VPS not found");
  const body = await readJsonObject(request);
  const name = stringField(body, "name", { required: true, max: 100 });
  const region = stringField(body, "region", { max: 100 });
  const address = stringField(body, "address", { max: 253 });
  const protocols = body.protocols ? await submittedProtocols(body) : [{ type: parseProfileType(body.type), settings: parseProfileSettings(parseProfileType(body.type), { ...(await profileDefaults(parseProfileType(body.type))), ...submittedSettings(body) }) }];
  const { type, settings } = protocols[0]!;
  await env.DB.batch([
    env.DB.prepare("UPDATE profiles SET name=?,type=?,settings_json=?,protocols_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, type, JSON.stringify(settings), JSON.stringify(protocols), current.profile_id),
    env.DB.prepare("UPDATE nodes SET name=?,region=?,address=?,draft=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, region, address, id),
  ]);
  return json({ id, name, region, address, type, settings, protocols });
}

async function vpsInstall(id: string, env: Env): Promise<Response> {
  const node = await env.DB.prepare("SELECT name FROM nodes WHERE id=? AND enabled=1").bind(id).first<{ name: string }>();
  if (!node) throw new HttpError(404, "VPS not found");
  const install = await freshInstallTicket(id, env);
  return json({ id, ticket: install.ticket, expires_in_seconds: 900 });
}

async function createProfile(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const type = parseProfileType(body.type);
  const submitted = body.settings && typeof body.settings === "object" && !Array.isArray(body.settings) ? body.settings as Record<string, unknown> : {};
  const settings = parseProfileSettings(type, { ...(await profileDefaults(type)), ...submitted });
  await env.DB.prepare("INSERT INTO profiles(id,name,type,settings_json,protocols_json) VALUES(?,?,?,?,?)")
    .bind(id, name, type, JSON.stringify(settings), JSON.stringify([{ type, settings }]))
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
  const groupId = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const clientId = stringField(body, "client_id", { required: true, max: 64 });
  const client = await env.DB.prepare("SELECT id FROM clients WHERE id=? AND enabled=1").bind(clientId).first();
  if (!client) throw new HttpError(404, "client not found");
  const token = randomToken();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO subscription_groups(id,name) VALUES(?,?)").bind(groupId, name),
    env.DB.prepare("INSERT INTO subscription_group_nodes(group_id,node_id) SELECT ?,id FROM nodes WHERE enabled=1").bind(groupId),
    env.DB.prepare("INSERT INTO subscriptions(id,name,group_id,client_id,token_hash) VALUES(?,?,?,?,?)").bind(id, name, groupId, clientId, await sha256Hex(token)),
  ]);
  return json({ id, name, client_id: clientId, token }, { status: 201 });
}

async function createSubscriptionGroup(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const nodeIds = stringArray(body.node_ids, "node_ids");
  const clientNames = body.client_names === undefined ? [name] : stringArray(body.client_names, "client_names", 20);
  const placeholders = nodeIds.map(() => "?").join(",");
  const found = await env.DB.prepare(`SELECT id FROM nodes WHERE enabled=1 AND id IN (${placeholders})`).bind(...nodeIds).all();
  if (found.results.length !== nodeIds.length) throw new HttpError(400, "one or more VPS nodes are unavailable");

  const statements: D1PreparedStatement[] = [
    env.DB.prepare("INSERT INTO subscription_groups(id,name) VALUES(?,?)").bind(id, name),
    ...nodeIds.map((nodeId) => env.DB.prepare("INSERT INTO subscription_group_nodes(group_id,node_id) VALUES(?,?)").bind(id, nodeId)),
  ];
  const members: Array<{ id: string; name: string; token: string }> = [];
  for (const clientName of clientNames) {
    const clientId = randomUuid();
    const subscriptionId = randomUuid();
    const token = randomToken();
    statements.push(
      env.DB.prepare("INSERT INTO clients(id,name,uuid,hysteria2_password,trojan_password,tuic_password,shadowsocks_password) VALUES(?,?,?,?,?,?,?)")
        .bind(clientId, clientName, randomUuid(), randomToken(24), randomToken(24), randomToken(24), randomBase64(16)),
      env.DB.prepare("INSERT INTO subscriptions(id,name,group_id,client_id,token_hash) VALUES(?,?,?,?,?)")
        .bind(subscriptionId, name, id, clientId, await sha256Hex(token)),
    );
    members.push({ id: subscriptionId, name: clientName, token });
  }
  await env.DB.batch(statements);
  return json({ id, name, node_ids: nodeIds, members }, { status: 201 });
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
  const profile = await env.DB.prepare(`SELECT p.id,p.name,p.type,p.settings_json,p.protocols_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.agent_id=? AND n.enabled=1`)
    .bind(agentId)
    .first<ProfileRow>();
  if (!profile) throw new HttpError(404, "enabled node/profile not found");
  const clients = await env.DB.prepare(`SELECT DISTINCT c.id,c.name,c.uuid,c.hysteria2_password,c.trojan_password,c.tuic_password,c.shadowsocks_password
    FROM clients c JOIN subscriptions s ON s.client_id=c.id JOIN subscription_group_nodes sgn ON sgn.group_id=s.group_id
    JOIN nodes n ON n.id=sgn.node_id WHERE n.agent_id=? AND c.enabled=1 AND s.enabled=1 ORDER BY c.created_at`).bind(agentId).all<ClientRecord>();
  if (clients.results.length === 0) throw new HttpError(409, "请先创建包含此 VPS 的订阅客户端");
  const protocols = storedProtocols(profile).map(({ type, settings }) => ({ type: parseProfileType(type), settings: parseProfileSettings(parseProfileType(type), settings) }));
  const configJson = JSON.stringify(compileServerProfiles(protocols, clients.results), null, 2);
  const digest = await sha256Hex(configJson);
  const insert = await env.DB.prepare("INSERT INTO revisions(agent_id,profile_id,config_json,sha256) VALUES(?,?,?,?)")
    .bind(agentId, profile.id, configJson, digest)
    .run();
  const revision = Number(insert.meta.last_row_id);
  await env.DB.prepare("UPDATE agents SET desired_revision=?,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(revision, agentId).run();
  await env.DB.prepare("UPDATE nodes SET draft=0,updated_at=CURRENT_TIMESTAMP WHERE agent_id=?").bind(agentId).run();
  return json({ agent_id: agentId, desired_revision: revision, sha256: digest }, { status: 201 });
}

async function publishVps(id: string, env: Env): Promise<Response> {
  const node = await env.DB.prepare("SELECT agent_id FROM nodes WHERE id=? AND enabled=1").bind(id).first<{ agent_id: string | null }>();
  if (!node) throw new HttpError(404, "VPS not found");
  if (!node.agent_id) throw new HttpError(409, "请先安装 Agent");
  return publishAgent(node.agent_id, env);
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
  const ticket = stringField(body, "ticket", { required: true, max: 256 });
  const name = stringField(body, "name", { required: true, max: 100 });
  const hostname = stringField(body, "hostname", { required: true, max: 253 });
  const architecture = stringField(body, "architecture", { required: true, max: 32 });
  const os = stringField(body, "os", { required: true, max: 64 });
  const distro = stringField(body, "distro", { required: true, max: 64 });
  const distroVersion = stringField(body, "distro_version", { max: 64 });
  const libc = stringField(body, "libc", { required: true, max: 32 });
  const initSystem = stringField(body, "init_system", { required: true, max: 32 });
  const installMode = stringField(body, "install_mode", { required: true, max: 32 });
  const ticketHash = await sha256Hex(ticket);
  const id = await hmacHex(env.AGENT_TOKEN_SECRET, `agent-id:${ticket}`);
  const token = await hmacHex(env.AGENT_TOKEN_SECRET, `agent-token:${ticket}`);
  let use = await env.DB.prepare(`SELECT id,node_id,agent_id,used_at FROM install_tickets
    WHERE token_hash=? AND expires_at>CURRENT_TIMESTAMP
    AND EXISTS(SELECT 1 FROM nodes WHERE nodes.id=install_tickets.node_id AND nodes.enabled=1)`)
    .bind(ticketHash).first<{ id: string; node_id: string; agent_id: string | null; used_at: string | null }>();
  if (!use) throw new HttpError(401, "invalid or expired install ticket");
  if (use.agent_id) {
    if (use.agent_id !== id) throw new HttpError(409, "install ticket registration conflict");
    const existing = await env.DB.prepare("SELECT id FROM agents WHERE id=?").bind(id).first();
    if (existing) return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60, idempotent: true }, { status: 200 });
  }
  const consumed = await env.DB.prepare("UPDATE install_tickets SET used_at=CURRENT_TIMESTAMP,agent_id=? WHERE id=? AND agent_id IS NULL RETURNING node_id")
    .bind(id, use.id).first<{ node_id: string }>();
  if (!consumed) {
    use = await env.DB.prepare("SELECT id,node_id,agent_id,used_at FROM install_tickets WHERE id=? AND agent_id=?").bind(use.id, id)
      .first<{ id: string; node_id: string; agent_id: string; used_at: string }>();
    if (!use) throw new HttpError(409, "install registration is in progress; retry shortly");
  }
  const oldAgent = await env.DB.prepare("SELECT agent_id FROM nodes WHERE id=?").bind(use.node_id).first<{ agent_id: string | null }>();
  const statements: D1PreparedStatement[] = [env.DB.prepare("INSERT INTO agents(id,name,hostname,token_hash,os,distro,distro_version,architecture,libc,init_system,install_mode,public_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(
      id,
      name,
      hostname,
      await sha256Hex(token),
      os,
      distro,
      distroVersion,
      architecture,
      libc,
      initSystem,
      installMode,
      request.headers.get("cf-connecting-ip") ?? "",
    )];
  statements.push(env.DB.prepare(`UPDATE nodes SET agent_id=?,address=CASE WHEN address='' THEN ? ELSE address END,install_stage='registered',last_install_error_code=NULL,last_install_message='Agent registered',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .bind(id, request.headers.get("cf-connecting-ip") ?? "", use.node_id));
  statements.push(env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) VALUES(?,'registered','Agent registered','worker')").bind(use.node_id));
  if (oldAgent?.agent_id) statements.push(env.DB.prepare("DELETE FROM agents WHERE id=?").bind(oldAgent.agent_id));
  await env.DB.batch(statements);
  return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60 }, { status: 201 });
}

async function setEnabled(resource: string, id: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const enabled = booleanField(body, "enabled");
  const table = resource === "subscriptions" ? "subscriptions" : resource === "clients" ? "clients" : resource === "nodes" ? "nodes" : null;
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

const installStages = new Set(["ticket_created", "bootstrap_started", "agent_downloaded", "runtime_downloaded", "runtime_installed", "service_installed", "registered", "online", "upgrading", "upgraded", "failed"]);

async function installEvent(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request, 16 * 1024);
  const ticket = stringField(body, "ticket", { max: 256 });
  const stage = stringField(body, "stage", { required: true, max: 32 });
  if (!installStages.has(stage)) throw new HttpError(400, "invalid install stage");
  const errorCode = stringField(body, "error_code", { max: 64 });
  const message = stringField(body, "message", { max: 1024 });
  const source = stringField(body, "source", { max: 253 });
  let nodeId: string;
  if (ticket) {
    const ticketRow = await env.DB.prepare("SELECT node_id FROM install_tickets WHERE token_hash=? AND expires_at>CURRENT_TIMESTAMP")
      .bind(await sha256Hex(ticket)).first<{ node_id: string }>();
    if (!ticketRow) throw new HttpError(401, "invalid or expired install ticket");
    nodeId = ticketRow.node_id;
  } else {
    const agent = await requireAgent(request, env);
    const node = await env.DB.prepare("SELECT id FROM nodes WHERE agent_id=?").bind(agent.id).first<{ id: string }>();
    if (!node) throw new HttpError(404, "agent node not found");
    nodeId = node.id;
  }
  await env.DB.batch([
    env.DB.prepare("INSERT INTO install_events(node_id,stage,error_code,message,source) VALUES(?,?,?,?,?)")
      .bind(nodeId, stage, errorCode || null, message, source),
    env.DB.prepare("UPDATE nodes SET install_stage=?,last_install_error_code=?,last_install_message=?,last_install_source=?,last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .bind(stage, errorCode || null, message, source, nodeId),
  ]);
  console.log(JSON.stringify({ event: "install_stage", node_id: nodeId, stage, error_code: errorCode || null, source }));
  return json({ ok: true });
}

async function syncAgent(request: Request, env: Env): Promise<Response> {
  const agent = await requireAgent(request, env);
  const body = await readJsonObject(request);
  const reportedRevision = numberField(body, "current_revision", { min: 1, integer: true });
  const permissions = boundedPermissions(body.permissions);
  const updateAgent = env.DB.prepare(`UPDATE agents SET
    agent_version=?,singbox_version=?,public_ip=?,singbox_running=?,cpu_usage_percent=?,uptime_seconds=?,memory_total_bytes=?,memory_used_bytes=?,disk_total_bytes=?,disk_used_bytes=?,permissions_json=?,last_seen=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
    current_revision=CASE WHEN EXISTS(SELECT 1 FROM revisions WHERE id=? AND agent_id=?) THEN ? ELSE current_revision END
    WHERE id=?`)
    .bind(
      stringField(body, "agent_version", { max: 64 }),
      stringField(body, "singbox_version", { max: 128 }),
      request.headers.get("cf-connecting-ip") ?? "",
      booleanField(body, "singbox_running") ? 1 : 0,
      numberField(body, "cpu_usage_percent", { min: 0, max: 100 }),
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
    );
  await env.DB.batch([
    updateAgent,
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) SELECT id,'online','Agent heartbeat online','agent' FROM nodes WHERE agent_id=? AND install_stage<>'online'").bind(agent.id),
    env.DB.prepare("UPDATE nodes SET install_stage='online',last_install_error_code=NULL,last_install_message='Agent heartbeat online',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE agent_id=?").bind(agent.id),
  ]);
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
  const subscriptionRow = await env.DB.prepare(`SELECT s.group_id,c.id,c.name,c.uuid,c.hysteria2_password,c.trojan_password,c.tuic_password,c.shadowsocks_password FROM subscriptions s JOIN clients c ON c.id=s.client_id
    JOIN subscription_groups g ON g.id=s.group_id WHERE s.token_hash=? AND s.enabled=1 AND c.enabled=1 AND g.enabled=1`).bind(tokenHash).first<ClientRecord & { group_id: string }>();
  if (!subscriptionRow) throw new HttpError(404, "subscription not found");
  const client: ClientRecord = subscriptionRow;
  const nodes = await env.DB.prepare(`SELECT n.id,n.name,COALESCE(NULLIF(n.address,''),a.public_ip,'') AS address,p.type,p.settings_json,p.protocols_json
    FROM subscription_group_nodes sgn JOIN nodes n ON n.id=sgn.node_id JOIN profiles p ON p.id=n.profile_id
    LEFT JOIN agents a ON a.id=n.agent_id WHERE sgn.group_id=? AND n.enabled=1 ORDER BY n.created_at`).bind(subscriptionRow.group_id).all<NodeRecord>();
  const format = match[2];
  const output = format === "sing-box" ? singBoxSubscription(client, nodes.results) : format === "mihomo" ? mihomoSubscription(client, nodes.results) : uriSubscription(client, nodes.results);
  const contentType = format === "mihomo" ? "text/yaml; charset=utf-8" : format === "sing-box" ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
  return new Response(output, { headers: { "content-type": contentType, "cache-control": "private, max-age=60", "subscription-userinfo": "upload=0; download=0; total=0; expire=0" } });
}

export async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path.startsWith("/sub/")) return subscription(path, env);
  if (path === "/api/install/event" && request.method === "POST") return installEvent(request, env);
  if (path === "/api/agent/register" && request.method === "POST") return registerAgent(request, env);
  if (path === "/api/agent/sync" && request.method === "POST") return syncAgent(request, env);
  if (path === "/api/agent/result" && request.method === "POST") return agentResult(request, env);

  await requireAdmin(request, env);
  if (path === "/api/admin/state" && request.method === "GET") return listAdmin(env);
  if (path === "/api/admin/profile-defaults" && request.method === "GET") {
    const type = parseProfileType(url.searchParams.get("type"));
    return json({ type, settings: await profileDefaults(type) });
  }
  if (path === "/api/admin/profiles" && request.method === "POST") return createProfile(request, env);
  if (path === "/api/admin/clients" && request.method === "POST") return createClient(request, env);
  if (path === "/api/admin/subscriptions" && request.method === "POST") return createSubscription(request, env);
  if (path === "/api/admin/subscription-groups" && request.method === "POST") return createSubscriptionGroup(request, env);
  if (path === "/api/admin/nodes" && request.method === "POST") return bindNode(request, env);
  if (path === "/api/admin/vps" && request.method === "POST") return createVps(request, env);

  const vpsId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)$/);
  if (vpsId && request.method === "PUT") return updateVps(vpsId, request, env);
  const vpsInstallId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)\/install$/);
  if (vpsInstallId && request.method === "POST") return vpsInstall(vpsInstallId, env);
  const vpsPublishId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)\/publish$/);
  if (vpsPublishId && request.method === "POST") return publishVps(vpsPublishId, env);

  const publishId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/publish$/);
  if (publishId && request.method === "POST") return publishAgent(publishId, env);
  const rollbackId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/rollback$/);
  if (rollbackId && request.method === "POST") return rollbackAgent(rollbackId, request, env);
  const enabledMatch = /^\/api\/admin\/(subscriptions|clients|nodes)\/([^/]+)\/enabled$/.exec(path);
  if (enabledMatch && request.method === "POST") return setEnabled(enabledMatch[1] ?? "", enabledMatch[2] ?? "", request, env);
  throw new HttpError(404, "not found");
}
