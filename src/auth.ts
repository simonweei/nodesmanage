import { sha256Hex } from "./crypto";
import { HttpError } from "./http";

export interface AgentIdentity {
  id: string;
  name: string;
}

export function requireAdmin(request: Request): string {
  const accessEmail = request.headers.get("cf-access-authenticated-user-email")?.trim();
  if (accessEmail) return accessEmail;
  const hostname = new URL(request.url).hostname;
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]") {
    const localEmail = request.headers.get("x-admin-email")?.trim();
    if (localEmail) return localEmail;
  }
  throw new HttpError(401, "Cloudflare Access authentication required");
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
