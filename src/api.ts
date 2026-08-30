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

interface AdminNodeRow extends Record<string, unknown> { id: string; total_count: number }
interface AdminGroupRow extends Record<string, unknown> { id: string; total_count: number }
interface GroupNodeRow extends Record<string, unknown> { group_id: string; node_id: string }
interface AdminSubscriptionRow extends Record<string, unknown> { id: string; group_id: string; client_id: string; client_name: string; enabled: number }
interface RevisionClientRow { id: string; name: string; uuid: string; shadowsocks_password: string }

function routeParam(path: string, pattern: RegExp): string | null {
  return pattern.exec(path)?.[1] ?? null;
}

async function listAdmin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "200", 10) || 200));
  const offset = Math.min(10_000, Math.max(0, Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0));
  const statements = [
    env.DB.prepare(`SELECT n.id,n.agent_id,n.profile_id,n.name,n.region,
      COALESCE(NULLIF(n.address,''),a.public_ip,'') AS address,n.address AS configured_address,n.deployment_mode,n.enabled,n.draft,n.retiring,n.install_stage,n.last_install_error_code,n.last_install_message,n.last_install_source,n.last_install_at,n.created_at,n.updated_at,
      p.type,p.settings_json,p.protocols_json,a.hostname,a.os,a.distro,a.distro_version,a.architecture,a.libc,a.init_system,a.install_mode,a.agent_version,a.singbox_version,a.public_ip,
      a.current_revision,a.desired_revision,a.singbox_running,a.cpu_usage_percent,a.uptime_seconds,a.memory_total_bytes,a.memory_used_bytes,
      a.disk_total_bytes,a.disk_used_bytes,a.permissions_json,a.last_error,a.last_seen,COUNT(*) OVER() AS total_count
      FROM nodes n JOIN profiles p ON p.id=n.profile_id LEFT JOIN agents a ON a.id=n.agent_id ORDER BY n.created_at DESC LIMIT ? OFFSET ?`).bind(limit, offset),
    env.DB.prepare("SELECT id,name,enabled,created_at,updated_at,COUNT(*) OVER() AS total_count FROM subscription_groups ORDER BY created_at DESC LIMIT ? OFFSET ?").bind(limit, offset),
    env.DB.prepare(`WITH page AS (SELECT id FROM subscription_groups ORDER BY created_at DESC LIMIT ? OFFSET ?)
      SELECT sgn.group_id,sgn.node_id FROM subscription_group_nodes sgn JOIN page ON page.id=sgn.group_id`).bind(limit, offset),
    env.DB.prepare(`WITH page AS (SELECT id FROM subscription_groups ORDER BY created_at DESC LIMIT ? OFFSET ?)
      SELECT s.id,s.name,s.group_id,s.client_id,s.enabled,s.created_at,s.updated_at,c.name AS client_name
      FROM subscriptions s JOIN clients c ON c.id=s.client_id JOIN page ON page.id=s.group_id ORDER BY s.created_at DESC`).bind(limit, offset),
    env.DB.prepare(`WITH page_nodes AS (SELECT id FROM nodes ORDER BY created_at DESC LIMIT ? OFFSET ?)
      SELECT e.id,e.node_id,e.stage,e.error_code,e.message,e.source,e.created_at FROM install_events e JOIN page_nodes p ON p.id=e.node_id ORDER BY e.id DESC LIMIT 500`).bind(limit, offset),
    env.DB.prepare("SELECT id,subject_key,severity,kind,agent_id,node_id,message,occurrences,first_seen_at,last_seen_at FROM alerts WHERE status='open' ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END,last_seen_at DESC LIMIT 100"),
  ];
  const results = await env.DB.batch(statements);
  const nodes = results[0] as D1Result<AdminNodeRow>;
  const groups = results[1] as D1Result<AdminGroupRow>;
  const groupNodes = results[2] as D1Result<GroupNodeRow>;
  const subscriptions = results[3] as D1Result<AdminSubscriptionRow>;
  const installEvents = results[4] as D1Result<Record<string, unknown>>;
  const alerts = results[5] as D1Result<Record<string, unknown>>;
  const subscriptionGroups = groups.results.map((group) => ({
    ...group,
    nodes: groupNodes.results.filter((item) => item.group_id === group.id).map((item) => item.node_id),
    clients: subscriptions.results.filter((item) => item.group_id === group.id).map((item) => ({ id: item.client_id, name: item.client_name, subscription_id: item.id, enabled: item.enabled })),
  }));
  return json({
    vps: nodes.results,
    nodes: nodes.results,
    subscriptions: subscriptions.results,
    subscription_groups: subscriptionGroups,
    install_events: installEvents.results,
    alerts: alerts.results,
    page: { limit, offset, vps_total: Number(nodes.results[0]?.total_count ?? 0), subscription_group_total: Number(groups.results[0]?.total_count ?? 0) },
  });
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

function deploymentMode(value: unknown): "system" | "user" {
  if (value === undefined || value === null || value === "") return "system";
  if (value !== "system" && value !== "user") throw new HttpError(400, "deployment_mode must be system or user");
  return value;
}

function validateDeploymentPorts(mode: "system" | "user", profiles: ProtocolProfile[]): void {
  if (mode === "user" && profiles.some((profile) => profile.settings.listen_port <= 1024)) {
    throw new HttpError(400, "非 root 用户级部署只能使用 1025-65535 端口");
  }
}

async function submittedProtocols(body: Record<string, unknown>, mode: "system" | "user"): Promise<ProtocolProfile[]> {
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
  validateDeploymentPorts(mode, profiles);
  return profiles;
}

function storedProtocols(profile: ProfileRow): ProtocolProfile[] {
  if (profile.protocols_json) return JSON.parse(profile.protocols_json) as ProtocolProfile[];
  return [{ type: profile.type, settings: JSON.parse(profile.settings_json) as ProtocolProfile["settings"] }];
}

async function agentIdsForNodes(env: Env, nodeIds: string[]): Promise<string[]> {
  if (nodeIds.length === 0) return [];
  const placeholders = nodeIds.map(() => "?").join(",");
  const rows = await env.DB.prepare(`SELECT DISTINCT agent_id FROM nodes WHERE id IN (${placeholders}) AND agent_id IS NOT NULL`).bind(...nodeIds).all<{ agent_id: string }>();
  return rows.results.map((row) => row.agent_id);
}

async function agentIdsForGroups(env: Env, groupIds: string[]): Promise<string[]> {
  if (groupIds.length === 0) return [];
  const placeholders = groupIds.map(() => "?").join(",");
  const rows = await env.DB.prepare(`SELECT DISTINCT n.agent_id FROM subscription_group_nodes sgn JOIN nodes n ON n.id=sgn.node_id
    WHERE sgn.group_id IN (${placeholders}) AND n.agent_id IS NOT NULL`).bind(...groupIds).all<{ agent_id: string }>();
  return rows.results.map((row) => row.agent_id);
}

function enqueueReconcileStatement(env: Env, agentIds: string[], reason: string, operationId = randomUuid()): D1PreparedStatement | null {
  const unique = [...new Set(agentIds)];
  if (unique.length === 0) return null;
  if (unique.length > 8) throw new HttpError(400, "one update can affect at most 8 installed VPS nodes");
  const values = unique.map(() => "(?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)").join(",");
  return env.DB.prepare(`INSERT INTO reconcile_queue(agent_id,reason,operation_id,created_at,updated_at) VALUES ${values}
    ON CONFLICT(agent_id) DO UPDATE SET reason=excluded.reason,operation_id=excluded.operation_id,target_revision=NULL,attempts=0,last_error=NULL,updated_at=CURRENT_TIMESTAMP`)
    .bind(...unique.flatMap((agentId) => [agentId, reason, operationId]));
}

async function finishReconcile(env: Env, agentId: string, revision: number, operationId: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE reconcile_queue SET target_revision=?,updated_at=CURRENT_TIMESTAMP WHERE agent_id=? AND operation_id=? AND target_revision IS NULL").bind(revision, agentId, operationId),
    env.DB.prepare("DELETE FROM reconcile_queue WHERE agent_id=? AND operation_id=? AND target_revision=?").bind(agentId, operationId, revision),
  ]);
}

async function createRevisionForAgent(agentId: string, env: Env): Promise<number> {
  const results = await env.DB.batch([
    env.DB.prepare(`SELECT p.id,p.name,p.type,p.settings_json,p.protocols_json,n.enabled,n.retiring
      FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.agent_id=?`).bind(agentId),
    env.DB.prepare(`SELECT DISTINCT c.id,c.name,c.uuid,c.shadowsocks_password
      FROM clients c JOIN subscriptions s ON s.client_id=c.id JOIN subscription_groups g ON g.id=s.group_id
      JOIN subscription_group_nodes sgn ON sgn.group_id=s.group_id JOIN nodes n ON n.id=sgn.node_id
      WHERE n.agent_id=? AND n.enabled=1 AND n.retiring=0 AND g.enabled=1 AND c.enabled=1 AND s.enabled=1 ORDER BY c.created_at`).bind(agentId),
  ]);
  const profileResult = results[0] as D1Result<ProfileRow & { enabled: number; retiring: number }>;
  const clientsResult = results[1] as D1Result<RevisionClientRow>;
  const profile = profileResult.results[0] as (ProfileRow & { enabled: number; retiring: number }) | undefined;
  if (!profile) throw new HttpError(404, "agent node/profile not found");
  const clients: ClientRecord[] = profile.enabled && !profile.retiring ? clientsResult.results.map((row) => ({
    id: String(row.id), name: String(row.name), uuid: String(row.uuid), shadowsocks_password: String(row.shadowsocks_password),
  })) : [];
  const protocols = storedProtocols(profile).map(({ type, settings }) => ({ type: parseProfileType(type), settings: parseProfileSettings(parseProfileType(type), settings) }));
  const configJson = JSON.stringify(compileServerProfiles(protocols, clients), null, 2);
  const digest = await sha256Hex(configJson);
  const insert = await env.DB.prepare("INSERT INTO revisions(agent_id,profile_id,config_json,sha256) VALUES(?,?,?,?)")
    .bind(agentId, profile.id, configJson, digest).run();
  const revision = Number(insert.meta.last_row_id);
  await env.DB.batch([
    env.DB.prepare("UPDATE agents SET desired_revision=?,last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(revision, agentId),
    env.DB.prepare("UPDATE nodes SET draft=0,updated_at=CURRENT_TIMESTAMP WHERE agent_id=?").bind(agentId),
  ]);
  return revision;
}

export async function publishAgents(agentIds: string[], env: Env, reason = "configuration changed"): Promise<Array<{ agent_id: string; revision: number }>> {
  const unique = [...new Set(agentIds)];
  if (unique.length === 0) return [];
  const operationId = randomUuid();
  await enqueueReconcileStatement(env, unique, reason, operationId)!.run();
  const published: Array<{ agent_id: string; revision: number }> = [];
  try {
    for (const agentId of unique) {
      const revision = await createRevisionForAgent(agentId, env);
      published.push({ agent_id: agentId, revision });
      await finishReconcile(env, agentId, revision, operationId);
    }
  } catch (error) {
    console.error(JSON.stringify({ event: "reconcile_failed", reason, error: error instanceof Error ? error.message : String(error) }));
    throw error;
  }
  return published;
}

export async function reconcilePending(env: Env, limit = 4): Promise<void> {
  const pending = await env.DB.prepare("SELECT agent_id,reason,operation_id FROM reconcile_queue ORDER BY updated_at LIMIT ?").bind(limit).all<{ agent_id: string; reason: string; operation_id: string }>();
  for (const item of pending.results) {
    try {
      const revision = await createRevisionForAgent(item.agent_id, env);
      await finishReconcile(env, item.agent_id, revision, item.operation_id);
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 1024) : String(error).slice(0, 1024);
      await env.DB.prepare("UPDATE reconcile_queue SET attempts=attempts+1,last_error=?,updated_at=CURRENT_TIMESTAMP WHERE agent_id=?").bind(message, item.agent_id).run();
      console.error(JSON.stringify({ event: "reconcile_retry_failed", agent_id: item.agent_id, error: message }));
    }
  }
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
  const capacity = await env.DB.prepare("SELECT COUNT(*) AS count FROM nodes").first<{ count: number }>();
  if (Number(capacity?.count ?? 0) >= 200) throw new HttpError(409, "this control plane supports at most 200 VPS nodes");
  const id = randomUuid();
  const profileId = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const region = stringField(body, "region", { max: 100 });
  const address = stringField(body, "address", { max: 253 });
  const mode = deploymentMode(body.deployment_mode);
  const protocols = body.protocols ? await submittedProtocols(body, mode) : [{ type: parseProfileType(body.type), settings: parseProfileSettings(parseProfileType(body.type), { ...(await profileDefaults(parseProfileType(body.type), mode)), ...submittedSettings(body) }) }];
  validateDeploymentPorts(mode, protocols);
  const { type, settings } = protocols[0]!;
  const installTicketId = randomUuid();
  const ticket = randomToken(24);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO profiles(id,name,type,settings_json,protocols_json) VALUES(?,?,?,?,?)").bind(profileId, name, type, JSON.stringify(settings), JSON.stringify(protocols)),
    env.DB.prepare("INSERT INTO nodes(id,profile_id,name,region,address,deployment_mode,draft) VALUES(?,?,?,?,?,?,1)").bind(id, profileId, name, region, address, mode),
    env.DB.prepare("INSERT INTO install_tickets(id,node_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+15 minutes'))").bind(installTicketId, id, await sha256Hex(ticket)),
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) VALUES(?,'ticket_created','Install ticket created','worker')").bind(id),
  ]);
  return json({ id, name, region, address, deployment_mode: mode, type, settings, protocols, ticket, expires_in_seconds: 900 }, { status: 201 });
}

async function updateVps(id: string, request: Request, env: Env): Promise<Response> {
  const current = await env.DB.prepare("SELECT n.profile_id,n.agent_id,n.name,n.deployment_mode,p.type,p.settings_json,p.protocols_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.id=?").bind(id).first<ProfileRow & { profile_id: string; agent_id: string | null; deployment_mode: "system" | "user" }>();
  if (!current) throw new HttpError(404, "VPS not found");
  const body = await readJsonObject(request);
  const name = stringField(body, "name", { required: true, max: 100 });
  const region = stringField(body, "region", { max: 100 });
  const address = stringField(body, "address", { max: 253 });
  const mode = body.deployment_mode === undefined ? current.deployment_mode : deploymentMode(body.deployment_mode);
  if (current.agent_id && mode !== current.deployment_mode) throw new HttpError(409, "已安装 VPS 不能切换部署模式，请先安全退役后重新创建");
  const protocols = body.protocols ? await submittedProtocols(body, mode) : [{ type: parseProfileType(body.type), settings: parseProfileSettings(parseProfileType(body.type), { ...(await profileDefaults(parseProfileType(body.type), mode)), ...submittedSettings(body) }) }];
  validateDeploymentPorts(mode, protocols);
  const { type, settings } = protocols[0]!;
  const statements = [
    env.DB.prepare("UPDATE profiles SET name=?,type=?,settings_json=?,protocols_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, type, JSON.stringify(settings), JSON.stringify(protocols), current.profile_id),
    env.DB.prepare("UPDATE nodes SET name=?,region=?,address=?,deployment_mode=?,draft=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, region, address, mode, id),
  ];
  const queue = enqueueReconcileStatement(env, current.agent_id ? [current.agent_id] : [], "VPS profile updated");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = current.agent_id ? await publishAgents([current.agent_id], env, "VPS profile updated") : [];
  return json({ id, name, region, address, deployment_mode: mode, type, settings, protocols, published });
}

async function vpsInstall(id: string, env: Env): Promise<Response> {
  const node = await env.DB.prepare("SELECT name,deployment_mode FROM nodes WHERE id=? AND enabled=1").bind(id).first<{ name: string; deployment_mode: "system" | "user" }>();
  if (!node) throw new HttpError(404, "VPS not found");
  const install = await freshInstallTicket(id, env);
  return json({ id, ticket: install.ticket, deployment_mode: node.deployment_mode, expires_in_seconds: 900 });
}

async function createSubscriptionGroup(request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const capacity = await env.DB.prepare("SELECT COUNT(*) AS count FROM subscription_groups").first<{ count: number }>();
  if (Number(capacity?.count ?? 0) >= 200) throw new HttpError(409, "this control plane supports at most 200 subscription groups");
  const id = randomUuid();
  const name = stringField(body, "name", { required: true, max: 100 });
  const nodeIds = stringArray(body.node_ids, "node_ids", 8);
  const clientNames = body.client_names === undefined ? [name] : stringArray(body.client_names, "client_names", 10);
  const placeholders = nodeIds.map(() => "?").join(",");
  const found = await env.DB.prepare(`SELECT id,agent_id FROM nodes WHERE enabled=1 AND retiring=0 AND agent_id IS NOT NULL
    AND COALESCE(NULLIF(address,''),(SELECT public_ip FROM agents WHERE agents.id=nodes.agent_id),'')<>'' AND id IN (${placeholders})`).bind(...nodeIds).all<{ id: string; agent_id: string }>();
  if (found.results.length !== nodeIds.length) throw new HttpError(400, "one or more VPS nodes are unavailable");
  const members = await Promise.all(clientNames.map(async (clientName) => {
    const token = randomToken();
    return { id: randomUuid(), client_id: randomUuid(), name: clientName, uuid: randomUuid(), shadowsocks_password: randomBase64(16), token, token_hash: await sha256Hex(token) };
  }));
  const nodeValues = nodeIds.map(() => "(?,?)").join(",");
  const clientValues = members.map(() => "(?,?,?,?)").join(",");
  const subscriptionValues = members.map(() => "(?,?,?,?,?)").join(",");
  const agentIds = found.results.map((row) => row.agent_id);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO subscription_groups(id,name) VALUES(?,?)").bind(id, name),
    env.DB.prepare(`INSERT INTO subscription_group_nodes(group_id,node_id) VALUES ${nodeValues}`).bind(...nodeIds.flatMap((nodeId) => [id, nodeId])),
    env.DB.prepare(`INSERT INTO clients(id,name,uuid,shadowsocks_password) VALUES ${clientValues}`).bind(...members.flatMap((member) => [member.client_id, member.name, member.uuid, member.shadowsocks_password])),
    env.DB.prepare(`INSERT INTO subscriptions(id,name,group_id,client_id,token_hash) VALUES ${subscriptionValues}`).bind(...members.flatMap((member) => [member.id, name, id, member.client_id, member.token_hash])),
    enqueueReconcileStatement(env, agentIds, "subscription group created")!,
  ]);
  const published = await publishAgents(agentIds, env, "subscription group created");
  return json({ id, name, node_ids: nodeIds, members: members.map(({ id: subscriptionId, name: clientName, token }) => ({ id: subscriptionId, name: clientName, token })), published }, { status: 201 });
}

async function updateSubscriptionGroup(id: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const current = await env.DB.prepare("SELECT id,name,enabled FROM subscription_groups WHERE id=?").bind(id).first<{ id: string; name: string; enabled: number }>();
  if (!current) throw new HttpError(404, "subscription group not found");
  const name = body.name === undefined ? current.name : stringField(body, "name", { required: true, max: 100 });
  const enabled = body.enabled === undefined ? Boolean(current.enabled) : booleanField(body, "enabled");
  const nodeIds = stringArray(body.node_ids, "node_ids", 8);
  const oldAgents = await agentIdsForGroups(env, [id]);
  const placeholders = nodeIds.map(() => "?").join(",");
  const found = await env.DB.prepare(`SELECT id,agent_id FROM nodes WHERE enabled=1 AND retiring=0 AND agent_id IS NOT NULL
    AND id IN (${placeholders})`).bind(...nodeIds).all<{ id: string; agent_id: string }>();
  if (found.results.length !== nodeIds.length) throw new HttpError(400, "one or more VPS nodes are unavailable");
  const affected = [...new Set([...oldAgents, ...found.results.map((row) => row.agent_id)])];
  if (affected.length > 8) throw new HttpError(400, "one update can affect at most 8 installed VPS nodes");
  const values = nodeIds.map(() => "(?,?)").join(",");
  const statements = [
    env.DB.prepare("UPDATE subscription_groups SET name=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, enabled ? 1 : 0, id),
    env.DB.prepare("DELETE FROM subscription_group_nodes WHERE group_id=?").bind(id),
    env.DB.prepare(`INSERT INTO subscription_group_nodes(group_id,node_id) VALUES ${values}`).bind(...nodeIds.flatMap((nodeId) => [id, nodeId])),
  ];
  const queue = enqueueReconcileStatement(env, affected, "subscription group updated");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = await publishAgents(affected, env, "subscription group updated");
  return json({ id, name, enabled, node_ids: nodeIds, published });
}

async function addSubscriptionClient(groupId: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const name = stringField(body, "name", { required: true, max: 100 });
  const group = await env.DB.prepare("SELECT id,name FROM subscription_groups WHERE id=? AND enabled=1").bind(groupId).first<{ id: string; name: string }>();
  if (!group) throw new HttpError(404, "enabled subscription group not found");
  const agents = await agentIdsForGroups(env, [groupId]);
  const clientId = randomUuid();
  const subscriptionId = randomUuid();
  const token = randomToken();
  const statements = [
    env.DB.prepare("INSERT INTO clients(id,name,uuid,shadowsocks_password) VALUES(?,?,?,?)").bind(clientId, name, randomUuid(), randomBase64(16)),
    env.DB.prepare("INSERT INTO subscriptions(id,name,group_id,client_id,token_hash) VALUES(?,?,?,?,?)").bind(subscriptionId, group.name, groupId, clientId, await sha256Hex(token)),
  ];
  const queue = enqueueReconcileStatement(env, agents, "subscription client added");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = await publishAgents(agents, env, "subscription client added");
  return json({ id: subscriptionId, client_id: clientId, name, token, published }, { status: 201 });
}

async function rotateSubscriptionToken(id: string, env: Env): Promise<Response> {
  const token = randomToken();
  const result = await env.DB.prepare("UPDATE subscriptions SET token_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=? RETURNING id,name").bind(await sha256Hex(token), id).first<{ id: string; name: string }>();
  if (!result) throw new HttpError(404, "subscription not found");
  return json({ id, name: result.name, token });
}

async function deleteSubscription(id: string, env: Env): Promise<Response> {
  const row = await env.DB.prepare("SELECT group_id,client_id FROM subscriptions WHERE id=?").bind(id).first<{ group_id: string; client_id: string }>();
  if (!row) throw new HttpError(404, "subscription not found");
  const agents = await agentIdsForGroups(env, [row.group_id]);
  const statements = [
    env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(id),
    env.DB.prepare("DELETE FROM clients WHERE id=? AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE client_id=?)").bind(row.client_id, row.client_id),
  ];
  const queue = enqueueReconcileStatement(env, agents, "subscription deleted");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = await publishAgents(agents, env, "subscription deleted");
  return json({ id, deleted: true, published });
}

async function deleteClient(id: string, env: Env): Promise<Response> {
  const groups = await env.DB.prepare("SELECT DISTINCT group_id FROM subscriptions WHERE client_id=?").bind(id).all<{ group_id: string }>();
  const agents = await agentIdsForGroups(env, groups.results.map((row) => row.group_id));
  const result = await env.DB.prepare("SELECT id FROM clients WHERE id=?").bind(id).first();
  if (!result) throw new HttpError(404, "client not found");
  const statements = [env.DB.prepare("DELETE FROM clients WHERE id=?").bind(id)];
  const queue = enqueueReconcileStatement(env, agents, "client deleted");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = await publishAgents(agents, env, "client deleted");
  return json({ id, deleted: true, published });
}

async function deleteSubscriptionGroup(id: string, env: Env): Promise<Response> {
  const clients = await env.DB.prepare("SELECT client_id FROM subscriptions WHERE group_id=?").bind(id).all<{ client_id: string }>();
  const agents = await agentIdsForGroups(env, [id]);
  const group = await env.DB.prepare("SELECT id FROM subscription_groups WHERE id=?").bind(id).first();
  if (!group) throw new HttpError(404, "subscription group not found");
  const statements = [env.DB.prepare("DELETE FROM subscription_groups WHERE id=?").bind(id)];
  const queue = enqueueReconcileStatement(env, agents, "subscription group deleted");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  if (clients.results.length) {
    const placeholders = clients.results.map(() => "?").join(",");
    const ids = clients.results.map((row) => row.client_id);
    await env.DB.prepare(`DELETE FROM clients WHERE id IN (${placeholders}) AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE subscriptions.client_id=clients.id)`).bind(...ids).run();
  }
  const published = await publishAgents(agents, env, "subscription group deleted");
  return json({ id, deleted: true, published });
}

async function deleteVps(id: string, request: Request, env: Env): Promise<Response> {
  const node = await env.DB.prepare(`SELECT n.agent_id,n.profile_id,n.retiring,a.current_revision,a.desired_revision
    FROM nodes n LEFT JOIN agents a ON a.id=n.agent_id WHERE n.id=?`).bind(id).first<{ agent_id: string | null; profile_id: string; retiring: number; current_revision: number | null; desired_revision: number | null }>();
  if (!node) throw new HttpError(404, "VPS not found");
  const force = new URL(request.url).searchParams.get("force") === "true";
  if (node.agent_id && !node.retiring && !force) {
    await env.DB.batch([
      env.DB.prepare("UPDATE nodes SET enabled=0,retiring=1,draft=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id),
      enqueueReconcileStatement(env, [node.agent_id], "VPS retirement requested")!,
    ]);
    const published = await publishAgents([node.agent_id], env, "VPS retirement requested");
    return json({ id, retiring: true, published }, { status: 202 });
  }
  if (node.agent_id && !force && node.current_revision !== node.desired_revision) throw new HttpError(409, "wait for the retirement revision to be applied or use force=true");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM nodes WHERE id=?").bind(id),
    env.DB.prepare("DELETE FROM agents WHERE id=?").bind(node.agent_id),
    env.DB.prepare("DELETE FROM profiles WHERE id=?").bind(node.profile_id),
  ]);
  return json({ id, deleted: true, forced: force });
}

async function publishAgent(agentId: string, env: Env): Promise<Response> {
  const published = await publishAgents([agentId], env, "manual publish");
  const revision = published[0]!.revision;
  return json({ agent_id: agentId, desired_revision: revision }, { status: 201 });
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
  const claim = stringField(body, "claim", { required: true, max: 128 }).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(claim)) throw new HttpError(400, "claim must be 32 random bytes encoded as hexadecimal");
  const name = stringField(body, "name", { required: true, max: 100 });
  const hostname = stringField(body, "hostname", { required: true, max: 253 });
  const architecture = stringField(body, "architecture", { required: true, max: 32 });
  const os = stringField(body, "os", { required: true, max: 64 });
  const distro = stringField(body, "distro", { required: true, max: 64 });
  const distroVersion = stringField(body, "distro_version", { max: 64 });
  const libc = stringField(body, "libc", { required: true, max: 32 });
  const initSystem = stringField(body, "init_system", { required: true, max: 32 });
  const installMode = stringField(body, "install_mode", { required: true, max: 32 });
  if (installMode !== "system" && installMode !== "user") throw new HttpError(400, "install_mode must be system or user");
  const ticketHash = await sha256Hex(ticket);
  const claimHash = await sha256Hex(claim);
  const id = await hmacHex(env.AGENT_TOKEN_SECRET, `agent-id:${ticket}:${claim}`);
  const token = await hmacHex(env.AGENT_TOKEN_SECRET, `agent-token:${ticket}:${claim}`);
  let use = await env.DB.prepare(`SELECT t.id,t.node_id,t.agent_id,t.claim_hash,t.used_at,n.deployment_mode FROM install_tickets t JOIN nodes n ON n.id=t.node_id
    WHERE t.token_hash=? AND t.expires_at>CURRENT_TIMESTAMP AND n.enabled=1`)
    .bind(ticketHash).first<{ id: string; node_id: string; agent_id: string | null; claim_hash: string | null; used_at: string | null; deployment_mode: string }>();
  if (!use) throw new HttpError(401, "invalid or expired install ticket");
  if (use.deployment_mode !== installMode) throw new HttpError(409, `installer mode ${installMode} does not match VPS deployment mode ${use.deployment_mode}`);
  const claimed = await env.DB.prepare(`UPDATE install_tickets SET claim_hash=COALESCE(claim_hash,?)
    WHERE id=? AND (claim_hash IS NULL OR claim_hash=?) RETURNING id`).bind(claimHash, use.id, claimHash).first();
  if (!claimed) throw new HttpError(409, "install ticket was claimed by another installer");
  if (use.agent_id) {
    if (use.agent_id !== id) throw new HttpError(409, "install ticket registration conflict");
    const existing = await env.DB.prepare("SELECT id FROM agents WHERE id=?").bind(id).first();
    if (existing) return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60, idempotent: true }, { status: 200 });
  }
  const oldAgent = await env.DB.prepare("SELECT agent_id FROM nodes WHERE id=?").bind(use.node_id).first<{ agent_id: string | null }>();
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("UPDATE install_tickets SET used_at=CURRENT_TIMESTAMP,agent_id=? WHERE id=? AND claim_hash=? AND expires_at>CURRENT_TIMESTAMP AND (agent_id IS NULL OR agent_id=?)")
      .bind(id, use.id, claimHash, id),
    env.DB.prepare(`INSERT INTO agents(id,name,hostname,token_hash,os,distro,distro_version,architecture,libc,init_system,install_mode,public_ip)
      SELECT ?,?,?,?,?,?,?,?,?,?,?,? FROM install_tickets WHERE id=? AND claim_hash=? AND agent_id=? AND expires_at>CURRENT_TIMESTAMP
      ON CONFLICT(id) DO NOTHING`)
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
      use.id,
      claimHash,
      id,
    ),
  ];
  statements.push(env.DB.prepare(`UPDATE nodes SET agent_id=?,address=CASE WHEN address='' THEN ? ELSE address END,install_stage='registered',last_install_error_code=NULL,last_install_message='Agent registered',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .bind(id, request.headers.get("cf-connecting-ip") ?? "", use.node_id));
  statements.push(env.DB.prepare(`INSERT INTO install_events(node_id,stage,message,source)
    SELECT ?,'registered','Agent registered','worker' WHERE NOT EXISTS(
      SELECT 1 FROM install_events WHERE node_id=? AND stage='registered' AND created_at>datetime('now','-1 minute'))`).bind(use.node_id, use.node_id));
  if (oldAgent?.agent_id && oldAgent.agent_id !== id) statements.push(env.DB.prepare("DELETE FROM agents WHERE id=?").bind(oldAgent.agent_id));
  await env.DB.batch(statements);
  return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60, idempotent: Boolean(use.agent_id) }, { status: use.agent_id ? 200 : 201 });
}

async function setEnabled(resource: string, id: string, request: Request, env: Env): Promise<Response> {
  const body = await readJsonObject(request);
  const enabled = booleanField(body, "enabled");
  let agents: string[] = [];
  if (resource === "subscription-groups") agents = await agentIdsForGroups(env, [id]);
  if (resource === "subscriptions") {
    const row = await env.DB.prepare("SELECT group_id FROM subscriptions WHERE id=?").bind(id).first<{ group_id: string }>();
    if (row) agents = await agentIdsForGroups(env, [row.group_id]);
  }
  if (resource === "clients") {
    const groups = await env.DB.prepare("SELECT DISTINCT group_id FROM subscriptions WHERE client_id=?").bind(id).all<{ group_id: string }>();
    agents = await agentIdsForGroups(env, groups.results.map((row) => row.group_id));
  }
  if (resource === "nodes") agents = await agentIdsForNodes(env, [id]);
  const table = resource === "subscription-groups" ? "subscription_groups" : resource === "subscriptions" ? "subscriptions" : resource === "clients" ? "clients" : resource === "nodes" ? "nodes" : null;
  if (!table) throw new HttpError(404, "resource not found");
  const found = await env.DB.prepare(`SELECT id FROM ${table} WHERE id=?`).bind(id).first();
  if (!found) throw new HttpError(404, "record not found");
  const statements = [env.DB.prepare(`UPDATE ${table} SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(enabled ? 1 : 0, id)];
  const queue = enqueueReconcileStatement(env, agents, `${resource} ${enabled ? "enabled" : "disabled"}`);
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = await publishAgents(agents, env, `${resource} ${enabled ? "enabled" : "disabled"}`);
  return json({ id, enabled, published });
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
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) SELECT id,'online','Agent heartbeat online','agent' FROM nodes WHERE agent_id=? AND install_stage NOT IN ('online','failed')").bind(agent.id),
    env.DB.prepare("UPDATE nodes SET install_stage='online',last_install_error_code=NULL,last_install_message='Agent heartbeat online',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE agent_id=? AND install_stage<>'failed'").bind(agent.id),
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
  const subscriptionRow = await env.DB.prepare(`SELECT s.group_id,c.id,c.name,c.uuid,c.shadowsocks_password FROM subscriptions s JOIN clients c ON c.id=s.client_id
    JOIN subscription_groups g ON g.id=s.group_id WHERE s.token_hash=? AND s.enabled=1 AND c.enabled=1 AND g.enabled=1`).bind(tokenHash).first<ClientRecord & { group_id: string }>();
  if (!subscriptionRow) throw new HttpError(404, "subscription not found");
  const client: ClientRecord = subscriptionRow;
  const nodes = await env.DB.prepare(`SELECT n.id,n.name,COALESCE(NULLIF(n.address,''),a.public_ip,'') AS address,p.type,p.settings_json,p.protocols_json
    FROM subscription_group_nodes sgn JOIN nodes n ON n.id=sgn.node_id JOIN profiles p ON p.id=n.profile_id
    JOIN agents a ON a.id=n.agent_id WHERE sgn.group_id=? AND n.enabled=1 AND n.retiring=0 AND n.draft=0
    AND COALESCE(NULLIF(n.address,''),a.public_ip,'')<>'' AND a.current_revision IS NOT NULL AND a.current_revision=a.desired_revision
    AND a.singbox_running=1 AND a.last_seen>datetime('now','-5 minutes') ORDER BY n.created_at`).bind(subscriptionRow.group_id).all<NodeRecord>();
  const format = match[2];
  const output = format === "sing-box" ? singBoxSubscription(client, nodes.results) : format === "mihomo" ? mihomoSubscription(client, nodes.results) : uriSubscription(client, nodes.results);
  const contentType = format === "mihomo" ? "text/yaml; charset=utf-8" : format === "sing-box" ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
  return new Response(output, { headers: { "content-type": contentType, "cache-control": "private, max-age=60", "subscription-userinfo": "upload=0; download=0; total=0; expire=0" } });
}

async function enforcePublicRateLimit(request: Request, env: Env): Promise<void> {
  const path = new URL(request.url).pathname;
  const authorization = request.headers.get("authorization") ?? "";
  const subscriptionToken = /^\/sub\/([a-f0-9]{64})\//.exec(path)?.[1] ?? "";
  const identity = authorization.startsWith("Bearer ") ? authorization.slice(7) : subscriptionToken || request.headers.get("cf-connecting-ip") || "unknown";
  const actor = await sha256Hex(identity);
  const route = path.startsWith("/sub/") ? "subscription" : path;
  const result = await env.PUBLIC_RATE_LIMITER.limit({ key: `${route}:${actor}` });
  if (!result.success) {
    console.warn(JSON.stringify({ event: "rate_limited", route: path, actor: actor.slice(0, 12) }));
    throw new HttpError(429, "rate limit exceeded");
  }
}

export async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path.startsWith("/sub/")) { await enforcePublicRateLimit(request, env); return subscription(path, env); }
  if (path === "/api/install/event" && request.method === "POST") { await enforcePublicRateLimit(request, env); return installEvent(request, env); }
  if (path === "/api/agent/register" && request.method === "POST") { await enforcePublicRateLimit(request, env); return registerAgent(request, env); }
  if (path === "/api/agent/sync" && request.method === "POST") { await enforcePublicRateLimit(request, env); return syncAgent(request, env); }
  if (path === "/api/agent/result" && request.method === "POST") { await enforcePublicRateLimit(request, env); return agentResult(request, env); }

  await requireAdmin(request, env);
  if (path === "/api/admin/state" && request.method === "GET") return listAdmin(request, env);
  if (path === "/api/admin/profile-defaults" && request.method === "GET") {
    const type = parseProfileType(url.searchParams.get("type"));
    const mode = deploymentMode(url.searchParams.get("mode"));
    return json({ type, deployment_mode: mode, settings: await profileDefaults(type, mode) });
  }
  if (path === "/api/admin/subscription-groups" && request.method === "POST") return createSubscriptionGroup(request, env);
  if (path === "/api/admin/vps" && request.method === "POST") return createVps(request, env);

  const vpsId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)$/);
  if (vpsId && request.method === "PUT") return updateVps(vpsId, request, env);
  if (vpsId && request.method === "DELETE") return deleteVps(vpsId, request, env);
  const vpsInstallId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)\/install$/);
  if (vpsInstallId && request.method === "POST") return vpsInstall(vpsInstallId, env);
  const vpsPublishId = routeParam(path, /^\/api\/admin\/vps\/([^/]+)\/publish$/);
  if (vpsPublishId && request.method === "POST") return publishVps(vpsPublishId, env);

  const publishId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/publish$/);
  if (publishId && request.method === "POST") return publishAgent(publishId, env);
  const rollbackId = routeParam(path, /^\/api\/admin\/agents\/([^/]+)\/rollback$/);
  if (rollbackId && request.method === "POST") return rollbackAgent(rollbackId, request, env);
  const groupId = routeParam(path, /^\/api\/admin\/subscription-groups\/([^/]+)$/);
  if (groupId && request.method === "PUT") return updateSubscriptionGroup(groupId, request, env);
  if (groupId && request.method === "DELETE") return deleteSubscriptionGroup(groupId, env);
  const groupClientId = routeParam(path, /^\/api\/admin\/subscription-groups\/([^/]+)\/clients$/);
  if (groupClientId && request.method === "POST") return addSubscriptionClient(groupClientId, request, env);
  const rotateId = routeParam(path, /^\/api\/admin\/subscriptions\/([^/]+)\/rotate$/);
  if (rotateId && request.method === "POST") return rotateSubscriptionToken(rotateId, env);
  const subscriptionId = routeParam(path, /^\/api\/admin\/subscriptions\/([^/]+)$/);
  if (subscriptionId && request.method === "DELETE") return deleteSubscription(subscriptionId, env);
  const clientId = routeParam(path, /^\/api\/admin\/clients\/([^/]+)$/);
  if (clientId && request.method === "DELETE") return deleteClient(clientId, env);
  const enabledMatch = /^\/api\/admin\/(subscription-groups|subscriptions|clients|nodes)\/([^/]+)\/enabled$/.exec(path);
  if (enabledMatch && request.method === "POST") return setEnabled(enabledMatch[1] ?? "", enabledMatch[2] ?? "", request, env);
  throw new HttpError(404, "not found");
}
