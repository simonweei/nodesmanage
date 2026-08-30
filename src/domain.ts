import { randomBase64, realityKeypair } from "./crypto";
import { HttpError } from "./http";

export const PROFILE_TYPES = [
  "vless-reality-vision", "shadowsocks-aead",
] as const;
export type ProfileType = typeof PROFILE_TYPES[number];

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
  address: string;
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

export function parseProfileType(value: unknown): ProfileType {
  if (!PROFILE_TYPES.includes(value as ProfileType)) throw new HttpError(400, "unsupported profile type");
  return value as ProfileType;
}

export function parseProfileSettings(type: ProfileType, input: unknown): ProfileSettings {
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
  throw new HttpError(400, "unsupported profile type");
}

export async function profileDefaults(type: ProfileType, deploymentMode: "system" | "user" = "system"): Promise<ProfileSettings> {
  if (type === "vless-reality-vision") {
    const keys = await realityKeypair();
    return {
      listen_port: deploymentMode === "user" ? 8443 : 443, server_name: "www.microsoft.com", reality_handshake_server: "www.microsoft.com",
      reality_handshake_port: 443, reality_private_key: keys.private_key, reality_public_key: keys.public_key,
      reality_short_id: Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, "0")).join(""),
    };
  }
  if (type === "shadowsocks-aead") return { listen_port: 8388, shadowsocks_method: "2022-blake3-aes-128-gcm", shadowsocks_server_password: randomBase64(16) };
  throw new HttpError(400, "unsupported profile type");
}

export function compileServerConfig(type: ProfileType, settings: ProfileSettings, clients: ClientRecord[]): Record<string, unknown> {
  let inbound: Record<string, unknown>;
  const base = { tag: `${type}-in`, listen: "::", listen_port: settings.listen_port };
  switch (type) {
    case "vless-reality-vision":
      inbound = { ...base, type: "vless", users: clients.map((c) => ({ name: c.name, uuid: c.uuid, flow: "xtls-rprx-vision" })), tls: { enabled: true, server_name: settings.server_name, reality: { enabled: true, handshake: { server: settings.reality_handshake_server, server_port: settings.reality_handshake_port }, private_key: settings.reality_private_key, short_id: [settings.reality_short_id] } } };
      break;
    case "shadowsocks-aead":
      inbound = { ...base, type: "shadowsocks", network: "tcp", method: settings.shadowsocks_method, password: settings.shadowsocks_server_password, users: clients.map((c) => ({ name: c.name, password: c.shadowsocks_password })), multiplex: { enabled: true } };
      break;
  }
  return { log: { level: "info", timestamp: true }, inbounds: [inbound], outbounds: [{ type: "direct", tag: "direct" }, { type: "block", tag: "block" }] };
}

export function compileServerProfiles(profiles: ProtocolProfile[], clients: ClientRecord[]): Record<string, unknown> {
  const inbounds = profiles.flatMap(({ type, settings }) =>
    compileServerConfig(type, settings, clients).inbounds as Record<string, unknown>[],
  );
  return { log: { level: "info", timestamp: true }, inbounds, outbounds: [{ type: "direct", tag: "direct" }, { type: "block", tag: "block" }] };
}
