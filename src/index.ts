import { handleApi } from "./api";
import { handleAdminAuth, hasAdminSession } from "./auth";
import { HttpError, json } from "./http";
import { installScript } from "./install";
import { installManifest } from "./releases";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/healthz") return json({ ok: true });
      if (url.pathname === "/install.sh" && request.method === "GET") return installScript(url.origin);
      if (url.pathname === "/api/install/manifest" && request.method === "GET") return installManifest(request);
      if (url.pathname.startsWith("/api/auth/")) return await handleAdminAuth(request, env);
      if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/sub/")) return await handleApi(request, env);
      if (url.pathname === "/login") {
        if (await hasAdminSession(request, env)) return Response.redirect(`${url.origin}/`, 302);
        const loginUrl = new URL("/login-page", url);
        const asset = await env.ASSETS.fetch(new Request(loginUrl, request));
        return new Response(asset.body, { status: asset.status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
      }
      if ((url.pathname === "/" || url.pathname === "/index.html") && !(await hasAdminSession(request, env))) {
        return Response.redirect(`${url.origin}/login`, 302);
      }
      return await env.ASSETS.fetch(request);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, { status: error.status });
      console.error(JSON.stringify({ message: "unhandled request error", path: url.pathname, error: error instanceof Error ? error.message : String(error) }));
      return json({ error: "internal server error" }, { status: 500 });
    }
  },
  async scheduled(_controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const results = await env.DB.batch([
      env.DB.prepare("DELETE FROM install_tickets WHERE expires_at<datetime('now','-1 day')"),
      env.DB.prepare("DELETE FROM install_events WHERE created_at<datetime('now','-90 days')"),
    ]);
    console.log(JSON.stringify({ event: "install_cleanup", ticket_changes: results[0]?.meta.changes ?? 0, event_changes: results[1]?.meta.changes ?? 0 }));
  },
} satisfies ExportedHandler<Env>;
