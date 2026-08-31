import { randomBase64, realityKeypair } from "./crypto";
import { HttpError } from "./http";

export const PROFILE_TYPES = [
  "vless-reality-vision", "shadowsocks-aead", "vless-tls-websocket", "vless-tls-grpc",
  "hysteria2", "tuic", "trojan-tls", "trojan-tls-websocket",
] as const;
export type ProfileType = typeof PROFILE_TYPES[number];
export type IngressMode = "direct" | "cloudflare_tunnel";
export type TunnelKind = "none" | "quick" | "named";

export const ACME_PROFILE_TYPES = [
  "vless-tls-websocket", "vless-tls-grpc", "hysteria2", "tuic", "trojan-tls", "trojan-tls-websocket",
] as const satisfies readonly ProfileType[];
export type AcmeProfileType = typeof ACME_PROFILE_TYPES[number];

export const TUNNEL_PROFILE_TYPES = [
  "vless-tls-websocket", "trojan-tls-websocket",
] as const satisfies readonly ProfileType[];
export type TunnelProfileType = typeof TUNNEL_PROFILE_TYPES[number];

export const TUNNEL_EDGE_PORTS = {
  quick: [443],
  named: [443, 2053, 2083, 2087, 2096, 8443],
} as const satisfies Record<Exclude<TunnelKind, "none">, readonly number[]>;

export interface ProfileSettings {
  listen_port: number;
  server_name?: string;
  reality_private_key?: string;
  reality_public_key?: string;
  reality_short_id?: string;
  reality_handshake_server?: string;
  reality_handshake_port?: number;
  shadowsocks_method?: "2022-blake3-aes-128-gcm";
  shadowsocks_server_password?: string;
  server_address?: string;
  tls_server_name?: string;
  acme_email?: string;
  websocket_path?: string;
  websocket_host?: string;
  grpc_service_name?: string;
  hysteria2_obfs_password?: string;
}

export interface ClientRecord {
  id: string;
  name: string;
  uuid: string;
  shadowsocks_password: string;
}

export interface NodeRecord {
  id: string;
  name: string;
  connect_host: string;
  connect_port: number;
  ingress_mode: IngressMode;
  type: ProfileType;
  settings_json: string;
  protocols_json?: string | null;
}

export interface ProtocolProfile {
  type: ProfileType;
  settings: ProfileSettings;
}

function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new HttpError(400, "settings must be an object");
  return input as Record<string, unknown>;
}

function string(value: unknown, key: string, max = 1024): string {
  if (typeof value !== "string" || !value.trim() || value.length > max) throw new HttpError(400, `${key} is invalid`);
  return value.trim();
}

function port(value: unknown, key = "listen_port"): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 65535) throw new HttpError(400, `${key} must be a valid port`);
  return value;
}

function hostname(value: unknown, key: string): string {
  const result = string(value, key, 253).toLowerCase();
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(result)) {
    throw new HttpError(400, `${key} must be a valid domain name`);
  }
  return result;
}

function acmeSettings(value: Record<string, unknown>, result: ProfileSettings): void {
  result.tls_server_name = hostname(value.tls_server_name, "tls_server_name");
  result.server_address = hostname(value.server_address ?? value.tls_server_name, "server_address");
  const email = string(value.acme_email, "acme_email", 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "acme_email must be a valid email address");
  result.acme_email = email;
}

export function isAcmeProfile(type: ProfileType): type is AcmeProfileType {
  return (ACME_PROFILE_TYPES as readonly ProfileType[]).includes(type);
}

export function isTunnelProfile(type: ProfileType): type is TunnelProfileType {
  return (TUNNEL_PROFILE_TYPES as readonly ProfileType[]).includes(type);
}

export function tunnelEdgePort(kind: Exclude<TunnelKind, "none">, value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || !(TUNNEL_EDGE_PORTS[kind] as readonly number[]).includes(value)) {
    throw new HttpError(400, `Cloudflare ${kind} Tunnel 不支持该公网端口`);
  }
  return value;
}

export function ingressCapabilities(): Record<string, unknown> {
  return {
    direct: { protocols: [...PROFILE_TYPES] },
    cloudflare_tunnel: {
      quick: { protocols: [...TUNNEL_PROFILE_TYPES], edge_ports: [...TUNNEL_EDGE_PORTS.quick], default_edge_port: 443, multiple_protocols: false },
      named: { protocols: [...TUNNEL_PROFILE_TYPES], edge_ports: [...TUNNEL_EDGE_PORTS.named], default_edge_port: 443, multiple_protocols: false },
    },
  };
}

export function profileNetworks(type: ProfileType): readonly ("tcp" | "udp")[] {
  if (type === "hysteria2" || type === "tuic") return ["udp"];
  if (type === "shadowsocks-aead") return ["tcp", "udp"];
  return ["tcp"];
}

export function parseProfileType(value: unknown): ProfileType {
  if (!PROFILE_TYPES.includes(value as ProfileType)) throw new HttpError(400, "unsupported profile type");
  return value as ProfileType;
}

export function parseProfileSettings(type: ProfileType, input: unknown, ingressMode: IngressMode = "direct"): ProfileSettings {
  const value = object(input);
  const result: ProfileSettings = { listen_port: port(value.listen_port) };
  if (type === "vless-reality-vision") {
    result.reality_private_key = string(value.reality_private_key, "reality_private_key", 128);
    result.reality_public_key = string(value.reality_public_key, "reality_public_key", 128);
    const shortId = string(value.reality_short_id, "reality_short_id", 16).toLowerCase();
    if (!/^(?:[0-9a-f]{2}){1,8}$/.test(shortId)) throw new HttpError(400, "reality_short_id must be 2-16 hexadecimal characters with an even length");
    result.reality_short_id = shortId;
    result.server_name = string(value.server_name, "server_name", 253);
    result.reality_handshake_server = string(value.reality_handshake_server, "reality_handshake_server", 253);
    result.reality_handshake_port = port(value.reality_handshake_port, "reality_handshake_port");
    return result;
  }
  if (type === "shadowsocks-aead") {
    const method = string(value.shadowsocks_method, "shadowsocks_method", 64);
    if (method !== "2022-blake3-aes-128-gcm") throw new HttpError(400, "unsupported Shadowsocks method");
    result.shadowsocks_method = method;
    result.shadowsocks_server_password = string(value.shadowsocks_server_password, "shadowsocks_server_password", 128);
    return result;
  }
  if (isTunnelProfile(type) && ingressMode === "cloudflare_tunnel") {
    const path = string(value.websocket_path, "websocket_path", 256);
    if (!path.startsWith("/") || /[?#]/.test(path)) throw new HttpError(400, "websocket_path must start with / and cannot contain ? or #");
    result.websocket_path = path;
    return result;
  }
  if (isAcmeProfile(type)) {
    acmeSettings(value, result);
    if (type === "vless-tls-websocket" || type === "trojan-tls-websocket") {
      const path = string(value.websocket_path, "websocket_path", 256);
      if (!path.startsWith("/") || /[?#]/.test(path)) throw new HttpError(400, "websocket_path must start with / and cannot contain ? or #");
      result.websocket_path = path;
      result.websocket_host = hostname(value.websocket_host ?? value.tls_server_name, "websocket_host");
    } else if (type === "vless-tls-grpc") {
      const serviceName = string(value.grpc_service_name, "grpc_service_name", 128);
      if (!/^[A-Za-z0-9._-]+$/.test(serviceName)) throw new HttpError(400, "grpc_service_name is invalid");
      result.grpc_service_name = serviceName;
    } else if (type === "hysteria2") {
      result.hysteria2_obfs_password = string(value.hysteria2_obfs_password, "hysteria2_obfs_password", 128);
    }
    return result;
  }
  throw new HttpError(400, "unsupported profile type");
}

export async function profileDefaults(type: ProfileType, deploymentMode: "system" | "user" = "system", ingressMode: IngressMode = "direct"): Promise<ProfileSettings> {
  if (ingressMode === "cloudflare_tunnel" && isTunnelProfile(type)) {
    return { listen_port: 18080, websocket_path: "/proxy" };
  }
  if (type === "vless-reality-vision") {
    const keys = await realityKeypair();
    return {
      listen_port: deploymentMode === "user" ? 8443 : 443, server_name: "www.microsoft.com", reality_handshake_server: "www.microsoft.com",
      reality_handshake_port: 443, reality_private_key: keys.private_key, reality_public_key: keys.public_key,
      reality_short_id: Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, "0")).join(""),
    };
  }
  if (type === "shadowsocks-aead") return { listen_port: 8388, shadowsocks_method: "2022-blake3-aes-128-gcm", shadowsocks_server_password: randomBase64(16) };
  if (isAcmeProfile(type)) {
    const common = { server_address: "", tls_server_name: "", acme_email: "" };
    if (type === "vless-tls-websocket" || type === "trojan-tls-websocket") return { listen_port: 8443, ...common, websocket_path: "/proxy", websocket_host: common.tls_server_name };
    if (type === "vless-tls-grpc") return { listen_port: 443, ...common, grpc_service_name: "NodeManage" };
    if (type === "hysteria2") return { listen_port: 8443, ...common, hysteria2_obfs_password: randomBase64(24) };
    if (type === "tuic") return { listen_port: 10443, ...common };
    return { listen_port: 9443, ...common };
  }
  throw new HttpError(400, "unsupported profile type");
}

function managedTls(settings: ProfileSettings, alpn?: string[]): Record<string, unknown> {
  return {
    enabled: true,
    server_name: settings.tls_server_name,
    ...(alpn ? { alpn } : {}),
    acme: {
      domain: [settings.tls_server_name],
      data_directory: "/etc/nodemanage/acme",
      default_server_name: settings.tls_server_name,
      email: settings.acme_email,
      provider: "letsencrypt",
      disable_tls_alpn_challenge: true,
    },
  };
}

export function compileServerConfig(type: ProfileType, settings: ProfileSettings, clients: ClientRecord[], ingressMode: IngressMode = "direct"): Record<string, unknown> {
  let inbound: Record<string, unknown>;
  const base = { tag: `${type}-in`, listen: ingressMode === "cloudflare_tunnel" ? "127.0.0.1" : "::", listen_port: settings.listen_port };
  switch (type) {
    case "vless-reality-vision":
      inbound = { ...base, type: "vless", users: clients.map((c) => ({ name: c.name, uuid: c.uuid, flow: "xtls-rprx-vision" })), tls: { enabled: true, server_name: settings.server_name, reality: { enabled: true, handshake: { server: settings.reality_handshake_server, server_port: settings.reality_handshake_port }, private_key: settings.reality_private_key, short_id: [settings.reality_short_id] } } };
      break;
    case "shadowsocks-aead":
      inbound = { ...base, type: "shadowsocks", method: settings.shadowsocks_method, password: settings.shadowsocks_server_password, users: clients.map((c) => ({ name: c.name, password: c.shadowsocks_password })), multiplex: { enabled: true } };
      break;
    case "vless-tls-websocket":
      inbound = { ...base, type: "vless", users: clients.map((c) => ({ name: c.name, uuid: c.uuid })), ...(ingressMode === "direct" ? { tls: managedTls(settings) } : {}), transport: { type: "ws", path: settings.websocket_path } };
      break;
    case "vless-tls-grpc":
      inbound = { ...base, type: "vless", users: clients.map((c) => ({ name: c.name, uuid: c.uuid })), tls: managedTls(settings, ["h2"]), transport: { type: "grpc", service_name: settings.grpc_service_name } };
      break;
    case "hysteria2":
      inbound = { ...base, type: "hysteria2", users: clients.map((c) => ({ name: c.name, password: c.shadowsocks_password })), obfs: { type: "salamander", password: settings.hysteria2_obfs_password }, tls: managedTls(settings) };
      break;
    case "tuic":
      inbound = { ...base, type: "tuic", users: clients.map((c) => ({ name: c.name, uuid: c.uuid, password: c.shadowsocks_password })), congestion_control: "bbr", zero_rtt_handshake: false, tls: managedTls(settings) };
      break;
    case "trojan-tls":
      inbound = { ...base, type: "trojan", users: clients.map((c) => ({ name: c.name, password: c.shadowsocks_password })), tls: managedTls(settings), multiplex: { enabled: true } };
      break;
    case "trojan-tls-websocket":
      inbound = { ...base, type: "trojan", users: clients.map((c) => ({ name: c.name, password: c.shadowsocks_password })), ...(ingressMode === "direct" ? { tls: managedTls(settings) } : {}), transport: { type: "ws", path: settings.websocket_path } };
      break;
  }
  return { log: { level: "info", timestamp: true }, inbounds: [inbound], outbounds: [{ type: "direct", tag: "direct" }, { type: "block", tag: "block" }] };
}

export function compileServerProfiles(profiles: ProtocolProfile[], clients: ClientRecord[], ingressMode: IngressMode = "direct"): Record<string, unknown> {
  const inbounds = profiles.flatMap(({ type, settings }) =>
    compileServerConfig(type, settings, clients, ingressMode).inbounds as Record<string, unknown>[],
  );
  return { log: { level: "info", timestamp: true }, inbounds, outbounds: [{ type: "direct", tag: "direct" }, { type: "block", tag: "block" }] };
}
