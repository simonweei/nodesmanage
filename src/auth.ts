import { sha256Hex } from "./crypto";
import { HttpError, json, readJsonObject, stringField } from "./http";

export interface AgentIdentity {
  id: string;
  name: string;
}

const COOKIE_NAME = "nm_session";
const SESSION_SECONDS = 12 * 60 * 60;
export const MIN_ADMIN_PASSWORD_LENGTH = 6;
const encoder = new TextEncoder();

function base64Url(value: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function equalSecret(left: string, right: string): Promise<boolean> {
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", encoder.encode(left)), crypto.subtle.digest("SHA-256", encoder.encode(right))]);
  return crypto.subtle.timingSafeEqual(a, b);
}

function cookieValue(request: Request): string | null {
  const cookies = request.headers.get("cookie") ?? "";
  for (const part of cookies.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE_NAME) return rest.join("=");
  }
  return null;
}

function configuredPassword(env: Pick<Env, "ADMIN_PASSWORD">): string {
  if (typeof env.ADMIN_PASSWORD !== "string" || env.ADMIN_PASSWORD.length < MIN_ADMIN_PASSWORD_LENGTH) {
    throw new HttpError(503, `ADMIN_PASSWORD must be configured with at least ${MIN_ADMIN_PASSWORD_LENGTH} characters`);
  }
  return env.ADMIN_PASSWORD;
}

export async function hasAdminSession(request: Request, env: Pick<Env, "ADMIN_PASSWORD">): Promise<boolean> {
  const token = cookieValue(request);
  if (!token) return false;
  const [version, expiresText, signature, extra] = token.split(".");
  if (version !== "v1" || !expiresText || !signature || extra !== undefined) return false;
  const expires = Number(expiresText);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(expires) || expires <= now || expires > now + SESSION_SECONDS + 60) return false;
  const expected = await hmac(configuredPassword(env), `${version}.${expiresText}`);
  return equalSecret(signature, expected);
}

export async function requireAdmin(request: Request, env: Pick<Env, "ADMIN_PASSWORD">): Promise<void> {
  if (!(await hasAdminSession(request, env))) throw new HttpError(401, "admin login required");
}

function sessionCookie(request: Request, token: string, maxAge: number): string {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

export async function handleAdminAuth(request: Request, env: Pick<Env, "ADMIN_PASSWORD" | "LOGIN_RATE_LIMITER">): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (path === "/api/auth/session" && request.method === "GET") return json({ authenticated: await hasAdminSession(request, env) });
  if (path === "/api/auth/login" && request.method === "POST") {
    const actor = request.headers.get("cf-connecting-ip") ?? "unknown";
    const limited = await env.LOGIN_RATE_LIMITER.limit({ key: `admin-login:${actor}` });
    if (!limited.success) {
      console.warn(JSON.stringify({ event: "rate_limited", route: "admin_login", actor }));
      throw new HttpError(429, "登录尝试过多，请一分钟后重试");
    }
    const body = await readJsonObject(request, 4096);
    const supplied = stringField(body, "password", { required: true, max: 1024 });
    const valid = await equalSecret(supplied, configuredPassword(env));
    if (!valid) throw new HttpError(401, "密码错误");
    const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    const payload = `v1.${expires}`;
    const token = `${payload}.${await hmac(env.ADMIN_PASSWORD, payload)}`;
    return json({ ok: true, expires_at: new Date(expires * 1000).toISOString() }, { headers: { "set-cookie": sessionCookie(request, token, SESSION_SECONDS) } });
  }
  if (path === "/api/auth/logout" && request.method === "POST") {
    return json({ ok: true }, { headers: { "set-cookie": sessionCookie(request, "", 0) } });
  }
  throw new HttpError(404, "not found");
}

export async function requireAgent(request: Request, env: Env): Promise<AgentIdentity> {
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) throw new HttpError(401, "agent token required");
  const token = authorization.slice(7).trim();
  if (token.length < 32 || token.length > 256) throw new HttpError(401, "invalid agent token");
  const tokenHash = await sha256Hex(token);
  const agent = await env.DB.prepare("SELECT id, name FROM agents WHERE token_hash = ?").bind(tokenHash).first<AgentIdentity>();
  if (!agent) throw new HttpError(401, "invalid agent token");
  return agent;
}
