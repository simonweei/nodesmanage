import { handleApi, reconcilePending } from "./api";
import { handleAdminAuth, hasAdminSession } from "./auth";
import { HttpError, json } from "./http";
import { installScript } from "./install";
import { installManifest } from "./releases";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/healthz") {
        await env.DB.prepare("SELECT 1").first();
        const configured = typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length >= 12 && typeof env.AGENT_TOKEN_SECRET === "string" && env.AGENT_TOKEN_SECRET.length >= 32;
        return json({ ok: configured, database: "ready", secrets: configured ? "ready" : "invalid" }, { status: configured ? 200 : 503 });
      }
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
    await reconcilePending(env);
    const results = await env.DB.batch([
      env.DB.prepare("DELETE FROM install_tickets WHERE expires_at<datetime('now','-1 day')"),
      env.DB.prepare("DELETE FROM install_events WHERE created_at<datetime('now','-90 days')"),
      env.DB.prepare(`INSERT INTO alerts(subject_key,severity,kind,agent_id,node_id,message)
        SELECT 'agent-offline:'||a.id,'critical','agent_offline',a.id,n.id,'Agent has not reported for more than 5 minutes'
        FROM agents a JOIN nodes n ON n.agent_id=a.id WHERE n.enabled=1 AND (a.last_seen IS NULL OR a.last_seen<datetime('now','-5 minutes'))
        ON CONFLICT(subject_key) DO UPDATE SET status='open',occurrences=alerts.occurrences+1,last_seen_at=CURRENT_TIMESTAMP,resolved_at=NULL`),
      env.DB.prepare(`UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP,last_seen_at=CURRENT_TIMESTAMP
        WHERE kind='agent_offline' AND status='open' AND EXISTS(SELECT 1 FROM agents WHERE agents.id=alerts.agent_id AND agents.last_seen>=datetime('now','-5 minutes'))`),
      env.DB.prepare(`INSERT INTO alerts(subject_key,severity,kind,agent_id,node_id,message)
        SELECT 'config-failed:'||a.id,'critical','config_failed',a.id,n.id,COALESCE(a.last_error,'Configuration apply failed')
        FROM agents a JOIN nodes n ON n.agent_id=a.id WHERE a.last_error IS NOT NULL AND a.last_error<>''
        ON CONFLICT(subject_key) DO UPDATE SET status='open',message=excluded.message,occurrences=alerts.occurrences+1,last_seen_at=CURRENT_TIMESTAMP,resolved_at=NULL`),
      env.DB.prepare(`UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP,last_seen_at=CURRENT_TIMESTAMP
        WHERE kind='config_failed' AND status='open' AND EXISTS(SELECT 1 FROM agents WHERE agents.id=alerts.agent_id AND (agents.last_error IS NULL OR agents.last_error=''))`),
      env.DB.prepare(`INSERT INTO alerts(subject_key,severity,kind,agent_id,node_id,message)
        SELECT 'reconcile-failed:'||q.agent_id,'warning','reconcile_failed',q.agent_id,n.id,COALESCE(q.last_error,'Configuration reconciliation repeatedly failed')
        FROM reconcile_queue q JOIN nodes n ON n.agent_id=q.agent_id WHERE q.attempts>=3
        ON CONFLICT(subject_key) DO UPDATE SET status='open',message=excluded.message,occurrences=alerts.occurrences+1,last_seen_at=CURRENT_TIMESTAMP,resolved_at=NULL`),
      env.DB.prepare(`UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP,last_seen_at=CURRENT_TIMESTAMP
        WHERE kind='reconcile_failed' AND status='open' AND NOT EXISTS(SELECT 1 FROM reconcile_queue WHERE reconcile_queue.agent_id=alerts.agent_id)`),
    ]);
    console.log(JSON.stringify({ event: "maintenance", ticket_changes: results[0]?.meta.changes ?? 0, event_changes: results[1]?.meta.changes ?? 0, offline_alerts: results[2]?.meta.changes ?? 0, config_alerts: results[4]?.meta.changes ?? 0, reconcile_alerts: results[6]?.meta.changes ?? 0 }));
  },
} satisfies ExportedHandler<Env>;
