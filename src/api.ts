import { requireAdmin, requireAgent } from "./auth";
import { hmacHex, randomBase64, randomToken, randomUuid, sha256Hex } from "./crypto";
import { certificateRequirements, compileServerProfiles, ingressCapabilities, isAcmeProfile, isTunnelProfile, parseProfileSettings, parseProfileType, profileDefaults, profileNetworks, tunnelEdgePort, type CertificateRequirement, type ClientRecord, type IngressMode, type NodeRecord, type ProfileType, type ProtocolProfile, type TunnelKind } from "./domain";
import { booleanField, HttpError, json, numberField, readJsonObject, stringField } from "./http";
import { mihomoSubscription, shadowsocksSubscription, singBoxSubscription, v2rayNSubscription } from "./subscriptions";

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
type DeploymentMode = "system" | "user";
type DeploymentPolicy = "auto" | DeploymentMode;

function routeParam(path: string, pattern: RegExp): string | null {
  return pattern.exec(path)?.[1] ?? null;
}

async function listAdmin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "200", 10) || 200));
  const offset = Math.min(10_000, Math.max(0, Number.parseInt(url.searchParams.get("offset") ?? "0", 10) || 0));
  const statements = [
    env.DB.prepare(`SELECT n.id,n.agent_id,n.profile_id,n.name,n.region,
      n.ingress_mode,n.tunnel_kind,n.connect_host,n.connect_port,n.origin_port,n.edge_tls,n.ingress_status,n.ingress_verified_at,n.last_ingress_error,n.deployment_mode,n.deployment_policy,n.enabled,n.draft,n.retiring,n.install_stage,n.last_install_error_code,n.last_install_message,n.last_install_source,n.last_install_at,n.created_at,n.updated_at,
      p.type,p.settings_json,p.protocols_json,a.hostname,a.os,a.distro,a.distro_version,a.architecture,a.libc,a.init_system,a.install_mode,a.agent_version,a.singbox_version,a.cloudflared_version,a.observed_egress_ip,a.tunnel_running,a.tunnel_hostname,a.tunnel_error,
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

function deploymentPolicy(value: unknown): DeploymentPolicy {
  if (value === undefined || value === null || value === "") return "auto";
  if (value !== "auto" && value !== "system" && value !== "user") throw new HttpError(400, "deployment_policy must be auto, system or user");
  return value;
}

function configurationMode(policy: DeploymentPolicy): DeploymentMode {
  return policy === "system" ? "system" : "user";
}

function ingressMode(value: unknown): IngressMode {
  if (value === undefined || value === null || value === "") return "direct";
  if (value !== "direct" && value !== "cloudflare_tunnel") throw new HttpError(400, "ingress_mode must be direct or cloudflare_tunnel");
  return value;
}

function tunnelKind(value: unknown, mode: IngressMode): TunnelKind {
  if (mode === "direct") return "none";
  if (value !== "quick" && value !== "named") throw new HttpError(400, "tunnel_kind must be quick or named");
  return value;
}

function endpointHost(value: unknown, required: boolean, requiredMessage = "连接地址不能为空"): string {
  const host = stringField({ host: value }, "host", { max: 253 }).toLowerCase();
  if (required && !host) throw new HttpError(400, requiredMessage);
  if (!host) return "";
  const ipv6 = host.includes(":") && /^[0-9a-f:]+$/.test(host) && host.split(":").length >= 3;
  if (!ipv6 && (/[/\s@?#]/.test(host) || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host))) throw new HttpError(400, "connect_host must be a hostname or IP address without a scheme or port");
  return host;
}

function validateDeploymentPorts(mode: DeploymentPolicy, ingress: IngressMode, profiles: ProtocolProfile[]): void {
  if (ingress === "cloudflare_tunnel") {
    if (profiles.length > 2 || profiles.some((profile) => !isTunnelProfile(profile.type))) throw new HttpError(400, "Cloudflare Tunnel 模式仅支持 VLESS 或 Trojan WebSocket 协议");
    if (profiles.some((profile) => profile.settings.listen_port <= 1024)) throw new HttpError(400, "Cloudflare Tunnel 本地端口必须在 1025-65535 范围内");
    if (new Set(profiles.map((profile) => profile.settings.listen_port)).size !== profiles.length) throw new HttpError(400, "Tunnel 协议必须使用不同的本地端口");
    if (new Set(profiles.map((profile) => profile.settings.websocket_path)).size !== profiles.length) throw new HttpError(400, "Tunnel 协议必须使用不同的 WebSocket 路径");
    return;
  }
  if (mode === "user" && profiles.some((profile) => profile.settings.listen_port <= 1024)) {
    throw new HttpError(400, "非 root 用户级部署只能使用 1025-65535 端口");
  }
  if (mode === "user" && profiles.some((profile) => isAcmeProfile(profile.type))) {
    throw new HttpError(400, "TLS/ACME 协议需要监听 80 端口完成证书签发，仅支持 system/root 部署");
  }
  certificateRequirements(profiles, ingress);
  for (let i = 0; i < profiles.length; i++) {
    for (let j = i + 1; j < profiles.length; j++) {
      const left = profiles[i];
      const right = profiles[j];
      if (!left || !right || left.settings.listen_port !== right.settings.listen_port) continue;
      if (profileNetworks(left.type).some((network) => profileNetworks(right.type).includes(network))) {
        throw new HttpError(400, "同一传输层上的协议必须使用不同监听端口");
      }
    }
  }
}

function tunnelOriginPort(body: Record<string, unknown>, ingress: IngressMode, fallback = 18080): number {
  if (ingress !== "cloudflare_tunnel") throw new HttpError(400, "Tunnel 路由端口仅适用于 Cloudflare Tunnel");
  const value = body.origin_port === undefined ? fallback : body.origin_port;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 1024 || value > 65535) throw new HttpError(400, "Tunnel 路由端口必须在 1025-65535 范围内");
  return value;
}

function validateTunnelOrigin(originPort: number, profiles: ProtocolProfile[]): void {
  if (profiles.some((profile) => profile.settings.listen_port === originPort)) throw new HttpError(400, "Tunnel 路由端口不能与协议本地端口相同");
}

function validateTunnelProfiles(kind: TunnelKind, profiles: ProtocolProfile[]): void {
  if (kind !== "quick" && kind !== "named") throw new HttpError(400, "Cloudflare Tunnel 类型无效");
  if (kind === "quick" && profiles.length !== 1) throw new HttpError(400, "Quick Tunnel 只能启用一个协议");
  const edgePorts = profiles.map((profile) => tunnelEdgePort(kind, profile.settings.edge_port));
  if (new Set(edgePorts).size !== edgePorts.length) throw new HttpError(400, "Named Tunnel 的协议必须使用不同的 Cloudflare 公网端口");
}

function requiresSystemDeployment(ingress: IngressMode, profiles: ProtocolProfile[]): boolean {
  return ingress === "direct" && profiles.some((profile) => profile.settings.listen_port <= 1024 || isAcmeProfile(profile.type));
}

async function submittedProtocols(body: Record<string, unknown>, policy: DeploymentPolicy, ingress: IngressMode, connectHost: string): Promise<ProtocolProfile[]> {
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
    const defaultsMode: DeploymentMode = policy === "auto" ? (isAcmeProfile(type) ? "system" : "user") : policy;
    const settings = { ...(await profileDefaults(type, defaultsMode, ingress)), ...submitted };
    if (ingress === "direct" && isAcmeProfile(type)) {
      const email = stringField(body, "acme_email", { max: 254 }).toLowerCase();
      if (!email) throw new HttpError(400, "Direct TLS 协议必须填写公共 ACME 邮箱");
      Object.assign(settings, {
        server_address: connectHost,
        tls_server_name: connectHost,
        acme_email: email,
        ...(type === "vless-tls-websocket" || type === "trojan-tls-websocket" ? { websocket_host: connectHost } : {}),
      });
    }
    profiles.push({ type, settings: parseProfileSettings(type, settings, ingress) });
  }
  validateDeploymentPorts(policy, ingress, profiles);
  return profiles;
}

function storedProtocols(profile: ProfileRow): ProtocolProfile[] {
  if (profile.protocols_json) return JSON.parse(profile.protocols_json) as ProtocolProfile[];
  return [{ type: profile.type, settings: JSON.parse(profile.settings_json) as ProtocolProfile["settings"] }];
}

function storedProfileType(type: ProfileType): ProfileType {
  return type === "trojan-tls-websocket" ? "trojan-tls" : type;
}

async function certificateRequirementsForAgent(agentId: string, env: Env): Promise<CertificateRequirement[]> {
  const profile = await env.DB.prepare(`SELECT p.id,p.name,p.type,p.settings_json,p.protocols_json,n.ingress_mode
    FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.agent_id=?`).bind(agentId)
    .first<ProfileRow & { ingress_mode: IngressMode }>();
  if (!profile) return [];
  const protocols = storedProtocols(profile).map(({ type, settings }) => {
    const parsedType = parseProfileType(type);
    return { type: parsedType, settings: parseProfileSettings(parsedType, settings, profile.ingress_mode) };
  });
  return certificateRequirements(protocols, profile.ingress_mode);
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
    env.DB.prepare(`SELECT p.id,p.name,p.type,p.settings_json,p.protocols_json,n.enabled,n.retiring,n.ingress_mode
      FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.agent_id=?`).bind(agentId),
    env.DB.prepare(`SELECT DISTINCT c.id,c.name,c.uuid,c.shadowsocks_password
      FROM clients c JOIN subscriptions s ON s.client_id=c.id JOIN subscription_groups g ON g.id=s.group_id
      JOIN subscription_group_nodes sgn ON sgn.group_id=s.group_id JOIN nodes n ON n.id=sgn.node_id
      WHERE n.agent_id=? AND n.enabled=1 AND n.retiring=0 AND g.enabled=1 AND c.enabled=1 AND s.enabled=1 ORDER BY c.created_at`).bind(agentId),
  ]);
  const profileResult = results[0] as D1Result<ProfileRow & { enabled: number; retiring: number; ingress_mode: IngressMode }>;
  const clientsResult = results[1] as D1Result<RevisionClientRow>;
  const profile = profileResult.results[0] as (ProfileRow & { enabled: number; retiring: number; ingress_mode: IngressMode }) | undefined;
  if (!profile) throw new HttpError(404, "agent node/profile not found");
  const clients: ClientRecord[] = profile.enabled && !profile.retiring ? clientsResult.results.map((row) => ({
    id: String(row.id), name: String(row.name), uuid: String(row.uuid), shadowsocks_password: String(row.shadowsocks_password),
  })) : [];
  const protocols = storedProtocols(profile).map(({ type, settings }) => ({ type: parseProfileType(type), settings: parseProfileSettings(parseProfileType(type), settings, profile.ingress_mode) }));
  const configJson = JSON.stringify(compileServerProfiles(protocols, clients, profile.ingress_mode), null, 2);
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
  const policy = deploymentPolicy(body.deployment_policy ?? body.deployment_mode);
  const ingress = ingressMode(body.ingress_mode);
  const kind = tunnelKind(body.tunnel_kind, ingress);
  const hostMessage = kind === "named" ? "Named Tunnel 必须填写 Cloudflare Public Hostname" : "Direct 入口必须填写公网 IP 或域名";
  const connectHost = endpointHost(body.connect_host, ingress === "direct" || kind === "named", hostMessage);
  const protocols = await submittedProtocols(body, policy, ingress, connectHost);
  validateDeploymentPorts(policy, ingress, protocols);
  if (ingress === "cloudflare_tunnel") validateTunnelProfiles(kind, protocols);
  const systemRequired = requiresSystemDeployment(ingress, protocols);
  const mode: DeploymentMode = policy === "auto" ? (systemRequired ? "system" : "user") : policy;
  const { type, settings } = protocols[0]!;
  const connectPort = ingress === "cloudflare_tunnel" ? settings.edge_port! : settings.listen_port;
  const originPort = ingress === "cloudflare_tunnel" ? tunnelOriginPort(body, ingress) : settings.listen_port;
  if (ingress === "cloudflare_tunnel") validateTunnelOrigin(originPort, protocols);
  const ingressStatus = ingress === "direct" ? "configured" : "pending";
  const installTicketId = randomUuid();
  const ticket = randomToken(24);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO profiles(id,name,type,settings_json,protocols_json) VALUES(?,?,?,?,?)").bind(profileId, name, storedProfileType(type), JSON.stringify(settings), JSON.stringify(protocols)),
    env.DB.prepare("INSERT INTO nodes(id,profile_id,name,region,ingress_mode,tunnel_kind,connect_host,connect_port,origin_port,edge_tls,ingress_status,deployment_mode,deployment_policy,draft) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1)").bind(id, profileId, name, region, ingress, kind, connectHost, connectPort, originPort, ingress === "cloudflare_tunnel" ? 1 : 0, ingressStatus, mode, policy),
    env.DB.prepare("INSERT INTO install_tickets(id,node_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+15 minutes'))").bind(installTicketId, id, await sha256Hex(ticket)),
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) VALUES(?,'ticket_created','Install ticket created','worker')").bind(id),
  ]);
  return json({ id, name, region, ingress_mode: ingress, tunnel_kind: kind, connect_host: connectHost, connect_port: connectPort, origin_port: originPort, deployment_policy: policy, deployment_mode: mode, system_required: systemRequired, type, settings, protocols, ticket, expires_in_seconds: 900 }, { status: 201 });
}

async function updateVps(id: string, request: Request, env: Env): Promise<Response> {
  const current = await env.DB.prepare("SELECT n.profile_id,n.agent_id,n.name,n.deployment_mode,n.deployment_policy,n.ingress_mode,n.tunnel_kind,n.connect_host,n.connect_port,n.origin_port,p.type,p.settings_json,p.protocols_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.id=?").bind(id).first<ProfileRow & { profile_id: string; agent_id: string | null; deployment_mode: DeploymentMode; deployment_policy: DeploymentPolicy; ingress_mode: IngressMode; tunnel_kind: TunnelKind; connect_host: string; connect_port: number; origin_port: number }>();
  if (!current) throw new HttpError(404, "VPS not found");
  const body = await readJsonObject(request);
  const name = stringField(body, "name", { required: true, max: 100 });
  const region = stringField(body, "region", { max: 100 });
  const policy = body.deployment_policy === undefined && body.deployment_mode === undefined ? current.deployment_policy : deploymentPolicy(body.deployment_policy ?? body.deployment_mode);
  const ingress = body.ingress_mode === undefined ? current.ingress_mode : ingressMode(body.ingress_mode);
  const kind = tunnelKind(body.tunnel_kind ?? current.tunnel_kind, ingress);
  if (current.agent_id && (policy !== current.deployment_policy || ingress !== current.ingress_mode || kind !== current.tunnel_kind)) throw new HttpError(409, "已安装 VPS 不能切换部署或入口模式，请先安全退役后重新创建");
  const submittedHost = body.connect_host === undefined ? current.connect_host : body.connect_host;
  const hostMessage = kind === "named" ? "Named Tunnel 必须填写 Cloudflare Public Hostname" : "Direct 入口必须填写公网 IP 或域名";
  const connectHost = kind === "quick" ? current.connect_host : endpointHost(submittedHost, ingress === "direct" || kind === "named", hostMessage);
  if (current.agent_id && ingress === "cloudflare_tunnel" && connectHost !== current.connect_host) throw new HttpError(409, "已安装 Tunnel 的公网域名不能在线修改，请安全退役后重新创建");
  const protocols = await submittedProtocols(body, policy, ingress, connectHost);
  validateDeploymentPorts(policy, ingress, protocols);
  if (ingress === "cloudflare_tunnel") validateTunnelProfiles(kind, protocols);
  const systemRequired = requiresSystemDeployment(ingress, protocols);
  const mode: DeploymentMode = current.agent_id ? current.deployment_mode : policy === "auto" ? (systemRequired ? "system" : "user") : policy;
  if (current.agent_id) validateDeploymentPorts(mode, ingress, protocols);
  const { type, settings } = protocols[0]!;
  const connectPort = ingress === "cloudflare_tunnel" ? settings.edge_port! : settings.listen_port;
  const originPort = ingress === "cloudflare_tunnel" ? tunnelOriginPort(body, ingress, current.origin_port || 18080) : settings.listen_port;
  if (ingress === "cloudflare_tunnel") validateTunnelOrigin(originPort, protocols);
  if (current.agent_id && ingress === "cloudflare_tunnel" && originPort !== current.origin_port) throw new HttpError(409, "已安装 Tunnel 的本地端口不能在线修改，请安全退役后重新创建");
  const ingressStatus = ingress === "direct" ? "configured" : (current.connect_host ? "connected" : "pending");
  const statements = [
    env.DB.prepare("UPDATE profiles SET name=?,type=?,settings_json=?,protocols_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, storedProfileType(type), JSON.stringify(settings), JSON.stringify(protocols), current.profile_id),
    env.DB.prepare("UPDATE nodes SET name=?,region=?,ingress_mode=?,tunnel_kind=?,connect_host=?,connect_port=?,origin_port=?,edge_tls=?,ingress_status=?,ingress_verified_at=NULL,last_ingress_error=NULL,deployment_mode=?,deployment_policy=?,draft=1,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(name, region, ingress, kind, connectHost, connectPort, originPort, ingress === "cloudflare_tunnel" ? 1 : 0, ingressStatus, mode, policy, id),
  ];
  const queue = enqueueReconcileStatement(env, current.agent_id ? [current.agent_id] : [], "VPS profile updated");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
  const published = current.agent_id ? await publishAgents([current.agent_id], env, "VPS profile updated") : [];
  return json({ id, name, region, ingress_mode: ingress, tunnel_kind: kind, connect_host: connectHost, connect_port: connectPort, origin_port: originPort, deployment_policy: policy, deployment_mode: mode, system_required: systemRequired, type, settings, protocols, published });
}

async function vpsInstall(id: string, env: Env): Promise<Response> {
  const node = await env.DB.prepare("SELECT n.name,n.deployment_mode,n.deployment_policy,n.ingress_mode,n.tunnel_kind,n.connect_host,n.connect_port,n.origin_port,p.type,p.settings_json,p.protocols_json FROM nodes n JOIN profiles p ON p.id=n.profile_id WHERE n.id=? AND n.enabled=1").bind(id).first<ProfileRow & { name: string; deployment_mode: DeploymentMode; deployment_policy: DeploymentPolicy; ingress_mode: IngressMode; tunnel_kind: TunnelKind; connect_host: string; connect_port: number; origin_port: number }>();
  if (!node) throw new HttpError(404, "VPS not found");
  const install = await freshInstallTicket(id, env);
  return json({ id, ticket: install.ticket, deployment_policy: node.deployment_policy, deployment_mode: node.deployment_mode, system_required: requiresSystemDeployment(node.ingress_mode, storedProtocols(node)), ingress_mode: node.ingress_mode, tunnel_kind: node.tunnel_kind, connect_host: node.connect_host, connect_port: node.connect_port, origin_port: node.origin_port, expires_in_seconds: 900 });
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
  const found = await env.DB.prepare(`SELECT id,agent_id FROM nodes WHERE id IN (${placeholders})`).bind(...nodeIds).all<{ id: string; agent_id: string | null }>();
  if (found.results.length !== nodeIds.length) throw new HttpError(400, "one or more VPS nodes do not exist");
  const members = await Promise.all(clientNames.map(async (clientName) => {
    const token = randomToken();
    return { id: randomUuid(), client_id: randomUuid(), name: clientName, uuid: randomUuid(), shadowsocks_password: randomBase64(16), token, token_hash: await sha256Hex(token) };
  }));
  const nodeValues = nodeIds.map(() => "(?,?)").join(",");
  const clientValues = members.map(() => "(?,?,?,?)").join(",");
  const subscriptionValues = members.map(() => "(?,?,?,?,?)").join(",");
  const agentIds = found.results.flatMap((row) => row.agent_id ? [row.agent_id] : []);
  const statements = [
    env.DB.prepare("INSERT INTO subscription_groups(id,name) VALUES(?,?)").bind(id, name),
    env.DB.prepare(`INSERT INTO subscription_group_nodes(group_id,node_id) VALUES ${nodeValues}`).bind(...nodeIds.flatMap((nodeId) => [id, nodeId])),
    env.DB.prepare(`INSERT INTO clients(id,name,uuid,shadowsocks_password) VALUES ${clientValues}`).bind(...members.flatMap((member) => [member.client_id, member.name, member.uuid, member.shadowsocks_password])),
    env.DB.prepare(`INSERT INTO subscriptions(id,name,group_id,client_id,token_hash) VALUES ${subscriptionValues}`).bind(...members.flatMap((member) => [member.id, name, id, member.client_id, member.token_hash])),
  ];
  const queue = enqueueReconcileStatement(env, agentIds, "subscription group created");
  if (queue) statements.push(queue);
  await env.DB.batch(statements);
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
  const found = await env.DB.prepare(`SELECT id,agent_id FROM nodes WHERE id IN (${placeholders})`).bind(...nodeIds).all<{ id: string; agent_id: string | null }>();
  if (found.results.length !== nodeIds.length) throw new HttpError(400, "one or more VPS nodes do not exist");
  const affected = [...new Set([...oldAgents, ...found.results.flatMap((row) => row.agent_id ? [row.agent_id] : [])])];
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
  let use = await env.DB.prepare(`SELECT t.id,t.node_id,t.agent_id,t.claim_hash,t.used_at,n.deployment_mode,n.deployment_policy,n.ingress_mode,p.type,p.settings_json,p.protocols_json FROM install_tickets t JOIN nodes n ON n.id=t.node_id JOIN profiles p ON p.id=n.profile_id
    WHERE t.token_hash=? AND t.expires_at>CURRENT_TIMESTAMP AND n.enabled=1`)
    .bind(ticketHash).first<ProfileRow & { id: string; node_id: string; agent_id: string | null; claim_hash: string | null; used_at: string | null; deployment_mode: DeploymentMode; deployment_policy: DeploymentPolicy; ingress_mode: IngressMode }>();
  if (!use) throw new HttpError(401, "invalid or expired install ticket");
  if (use.deployment_policy !== "auto" && use.deployment_policy !== installMode) throw new HttpError(409, `installer mode ${installMode} does not match VPS deployment policy ${use.deployment_policy}`);
  if (use.agent_id && use.deployment_mode !== installMode) throw new HttpError(409, `install ticket is already bound to ${use.deployment_mode} mode`);
  try {
    validateDeploymentPorts(installMode, use.ingress_mode, storedProtocols(use));
  } catch (error) {
    if (error instanceof HttpError) throw new HttpError(409, `installer mode ${installMode} is incompatible with this VPS profile: ${error.message}`);
    throw error;
  }
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
    env.DB.prepare(`INSERT INTO agents(id,name,hostname,token_hash,os,distro,distro_version,architecture,libc,init_system,install_mode,observed_egress_ip)
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
  statements.push(env.DB.prepare(`UPDATE nodes SET agent_id=?,deployment_mode=(SELECT install_mode FROM agents WHERE id=?),install_stage='registered',last_install_error_code=NULL,last_install_message='Agent registered',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .bind(id, id, use.node_id));
  statements.push(env.DB.prepare(`INSERT INTO install_events(node_id,stage,message,source)
    SELECT ?,'registered','Agent registered','worker' WHERE NOT EXISTS(
      SELECT 1 FROM install_events WHERE node_id=? AND stage='registered' AND created_at>datetime('now','-1 minute'))`).bind(use.node_id, use.node_id));
  if (oldAgent?.agent_id && oldAgent.agent_id !== id) statements.push(env.DB.prepare("DELETE FROM agents WHERE id=?").bind(oldAgent.agent_id));
  await env.DB.batch(statements);
  const published = await publishAgents([id], env, "Agent registered");
  return json({ agent_id: id, agent_token: token, poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60, idempotent: Boolean(use.agent_id), published }, { status: use.agent_id ? 200 : 201 });
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

const installStages = new Set(["ticket_created", "bootstrap_started", "agent_downloaded", "runtime_downloaded", "tunnel_downloaded", "runtime_installed", "service_installed", "registered", "online", "upgrading", "upgraded", "failed"]);

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
  const tunnelRunning = booleanField(body, "tunnel_running");
  const ingressVerified = booleanField(body, "ingress_verified");
  const reportedTunnelHostname = stringField(body, "tunnel_hostname", { max: 253 }).toLowerCase();
  const tunnelError = stringField(body, "tunnel_error", { max: 1024 });
  const validQuickHostname = /^[a-z0-9-]+\.trycloudflare\.com$/.test(reportedTunnelHostname);
  const updateAgent = env.DB.prepare(`UPDATE agents SET
    agent_version=?,singbox_version=?,cloudflared_version=?,observed_egress_ip=?,singbox_running=?,tunnel_running=?,tunnel_hostname=?,tunnel_error=?,cpu_usage_percent=?,uptime_seconds=?,memory_total_bytes=?,memory_used_bytes=?,disk_total_bytes=?,disk_used_bytes=?,permissions_json=?,last_seen=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
    current_revision=CASE WHEN EXISTS(SELECT 1 FROM revisions WHERE id=? AND agent_id=?) THEN ? ELSE current_revision END
    WHERE id=?`)
    .bind(
      stringField(body, "agent_version", { max: 64 }),
      stringField(body, "singbox_version", { max: 128 }),
      stringField(body, "cloudflared_version", { max: 128 }),
      request.headers.get("cf-connecting-ip") ?? "",
      booleanField(body, "singbox_running") ? 1 : 0,
      tunnelRunning ? 1 : 0,
      reportedTunnelHostname,
      tunnelError || null,
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
    env.DB.prepare(`UPDATE nodes SET
      connect_host=CASE WHEN ingress_mode='cloudflare_tunnel' AND tunnel_kind='quick' AND ?=1 THEN ? ELSE connect_host END,
      ingress_status=CASE
        WHEN ingress_mode='direct' AND connect_host<>'' THEN 'configured'
        WHEN ingress_mode='cloudflare_tunnel' AND ?=1 AND ?=1 THEN 'verified'
        WHEN ingress_mode='cloudflare_tunnel' AND ?=1 THEN 'connected'
        WHEN ingress_mode='cloudflare_tunnel' AND ?<>'' THEN 'failed'
        ELSE 'pending' END,
      ingress_verified_at=CASE WHEN ingress_mode='cloudflare_tunnel' AND ?=1 AND ?=1 THEN CURRENT_TIMESTAMP ELSE ingress_verified_at END,
      last_ingress_error=CASE WHEN ingress_mode='cloudflare_tunnel' THEN NULLIF(?,'') ELSE last_ingress_error END,
      updated_at=CURRENT_TIMESTAMP WHERE agent_id=?`)
      .bind(validQuickHostname ? 1 : 0, reportedTunnelHostname, tunnelRunning ? 1 : 0, ingressVerified ? 1 : 0, tunnelRunning ? 1 : 0, tunnelError,
        tunnelRunning ? 1 : 0, ingressVerified ? 1 : 0, tunnelError, agent.id),
    env.DB.prepare("INSERT INTO install_events(node_id,stage,message,source) SELECT id,'online','Agent heartbeat online','agent' FROM nodes WHERE agent_id=? AND install_stage NOT IN ('online','failed')").bind(agent.id),
    env.DB.prepare("UPDATE nodes SET install_stage='online',last_install_error_code=NULL,last_install_message='Agent heartbeat online',last_install_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE agent_id=? AND install_stage<>'failed'").bind(agent.id),
  ]);
  const state = await env.DB.prepare("SELECT current_revision,desired_revision FROM agents WHERE id=?").bind(agent.id).first<{ current_revision: number | null; desired_revision: number | null }>();
  if (!state) throw new HttpError(404, "agent not found");
  if (state.desired_revision && state.desired_revision !== state.current_revision) {
    const revision = await env.DB.prepare("SELECT id,config_json,sha256 FROM revisions WHERE id=? AND agent_id=?")
      .bind(state.desired_revision, agent.id)
      .first<{ id: number; config_json: string; sha256: string }>();
    if (revision) return json({ desired_revision: revision.id, config_json: revision.config_json, sha256: revision.sha256, certificates: await certificateRequirementsForAgent(agent.id, env), poll_seconds: Number(env.AGENT_POLL_SECONDS) || 60 });
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
  const match = /^\/sub\/([a-f0-9]{64})\/(sing-box|mihomo|shadowsocks|uri)$/.exec(path);
  if (!match) throw new HttpError(404, "subscription not found");
  const tokenHash = await sha256Hex(match[1] ?? "");
  const subscriptionRow = await env.DB.prepare(`SELECT s.group_id,g.name AS group_name,c.id,c.name,c.uuid,c.shadowsocks_password FROM subscriptions s JOIN clients c ON c.id=s.client_id
    JOIN subscription_groups g ON g.id=s.group_id WHERE s.token_hash=? AND s.enabled=1 AND c.enabled=1 AND g.enabled=1`).bind(tokenHash).first<ClientRecord & { group_id: string; group_name: string }>();
  if (!subscriptionRow) throw new HttpError(404, "subscription not found");
  const client: ClientRecord = subscriptionRow;
  const nodes = await env.DB.prepare(`SELECT n.id,n.name,n.connect_host,n.connect_port,n.ingress_mode,p.type,p.settings_json,p.protocols_json
    FROM subscription_group_nodes sgn JOIN nodes n ON n.id=sgn.node_id JOIN profiles p ON p.id=n.profile_id
    JOIN agents a ON a.id=n.agent_id WHERE sgn.group_id=? AND n.enabled=1 AND n.retiring=0 AND n.draft=0
    AND n.connect_host<>'' AND ((n.ingress_mode='direct' AND n.ingress_status IN ('configured','verified')) OR (n.ingress_mode='cloudflare_tunnel' AND n.ingress_status='verified'))
    AND a.current_revision IS NOT NULL AND a.current_revision=a.desired_revision
    AND a.singbox_running=1 AND a.last_seen>datetime('now','-5 minutes') ORDER BY n.created_at`).bind(subscriptionRow.group_id).all<NodeRecord>();
  const format = match[2];
  const output = format === "sing-box" ? singBoxSubscription(client, nodes.results)
    : format === "mihomo" ? mihomoSubscription(client, nodes.results)
    : format === "shadowsocks" ? shadowsocksSubscription(client, nodes.results)
    : v2rayNSubscription(client, nodes.results);
  const contentType = format === "mihomo" ? "text/yaml; charset=utf-8"
    : format === "sing-box" || format === "shadowsocks" ? "application/json; charset=utf-8"
    : "text/plain; charset=utf-8";
  const title = String(subscriptionRow.group_name);
  return new Response(output, { headers: { "content-type": contentType, "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(title)}`, "cache-control": "private, max-age=60", "subscription-userinfo": "upload=0; download=0; total=0; expire=0" } });
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
  if (path === "/api/admin/ingress-capabilities" && request.method === "GET") return json(ingressCapabilities());
  if (path === "/api/admin/profile-defaults" && request.method === "GET") {
    const type = parseProfileType(url.searchParams.get("type"));
    const policy = deploymentPolicy(url.searchParams.get("mode"));
    const mode: DeploymentMode = policy === "auto" && isAcmeProfile(type) ? "system" : configurationMode(policy);
    const ingress = ingressMode(url.searchParams.get("ingress") ?? "direct");
    if (ingress === "cloudflare_tunnel" && !isTunnelProfile(type)) throw new HttpError(400, "该协议不支持 Cloudflare Tunnel 公网入口");
    return json({ type, deployment_policy: policy, deployment_mode: mode, system_required: policy === "auto" && ingress === "direct" && isAcmeProfile(type), ingress_mode: ingress, settings: await profileDefaults(type, mode, ingress) });
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
