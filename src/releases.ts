import { HttpError } from "./http";
import { AGENT_VERSION, RELEASE_DIGESTS, SING_BOX_VERSION } from "./generated-releases";

export function installManifest(request: Request): Response {
  const url = new URL(request.url);
  const os = url.searchParams.get("os") ?? "linux";
  const arch = url.searchParams.get("arch") as keyof typeof RELEASE_DIGESTS | null;
  if (os !== "linux" || !arch || !(arch in RELEASE_DIGESTS)) throw new HttpError(400, "unsupported install platform");
  const selected = RELEASE_DIGESTS[arch];
  const singBoxFile = `sing-box-${SING_BOX_VERSION}-linux-${arch}.tar.gz`;
  return Response.json({ schema_version: 1, channel: "stable", platform: { os, arch },
    agent: { version: AGENT_VERSION, urls: [`${url.origin}/downloads/v${AGENT_VERSION}/nodemanage-agent-linux-${arch}`], sha256: selected.agentSha256 },
    sing_box: { version: SING_BOX_VERSION, urls: [
      `${url.origin}/downloads/v${SING_BOX_VERSION}/${singBoxFile}`,
      `https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${singBoxFile}`,
    ], sha256: selected.singBoxSha256, archive_root: singBoxFile.replace(/\.tar\.gz$/, "") },
  }, { headers: { "cache-control": "public, max-age=300", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" } });
}
