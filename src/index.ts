import { handleApi } from "./api";
import { HttpError, json } from "./http";
import { installScript } from "./install";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/healthz") return json({ ok: true });
      if (url.pathname === "/install.sh" && request.method === "GET") return installScript(url.origin);
      if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/sub/")) return await handleApi(request, env);
      return await env.ASSETS.fetch(request);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, { status: error.status });
      console.error(JSON.stringify({ message: "unhandled request error", path: url.pathname, error: error instanceof Error ? error.message : String(error) }));
      return json({ error: "internal server error" }, { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
