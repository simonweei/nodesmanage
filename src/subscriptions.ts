import type { ClientRecord, NodeRecord, ProfileSettings } from "./domain";

interface ExpandedNode extends NodeRecord { settings: ProfileSettings }
const expand = (nodes: NodeRecord[]): ExpandedNode[] => nodes.flatMap((node) => {
  const profiles = node.protocols_json ? JSON.parse(node.protocols_json) as { type: NodeRecord["type"]; settings: ProfileSettings }[] : [{ type: node.type, settings: JSON.parse(node.settings_json) as ProfileSettings }];
  return profiles.map((profile) => ({ ...node, type: profile.type, settings: profile.settings }));
});
const uriHost = (address: string): string => address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
const yaml = (value: string): string => JSON.stringify(value);
const tag = (node: ExpandedNode): string => `${node.name} · ${node.type}`;

function singOutbound(client: ClientRecord, node: ExpandedNode): Record<string, unknown> {
  const common = { tag: tag(node), server: node.address, server_port: node.settings.listen_port };
  switch (node.type) {
    case "vless-reality-vision": return { ...common, type: "vless", uuid: client.uuid, flow: "xtls-rprx-vision", tls: { enabled: true, server_name: node.settings.server_name, reality: { enabled: true, public_key: node.settings.reality_public_key, short_id: node.settings.reality_short_id }, utls: { enabled: true, fingerprint: "chrome" } } };
    case "shadowsocks-aead": return { ...common, type: "shadowsocks", method: node.settings.shadowsocks_method, password: `${node.settings.shadowsocks_server_password}:${client.shadowsocks_password}`, multiplex: { enabled: true } };
  }
}

export function singBoxSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return JSON.stringify({ outbounds: expand(records).map((node) => singOutbound(client, node)) }, null, 2);
}

function mihomoProxy(client: ClientRecord, node: ExpandedNode): string[] {
  const s = node.settings;
  const lines = [`  - name: ${yaml(tag(node))}`, `    server: ${yaml(node.address)}`, `    port: ${s.listen_port}`];
  switch (node.type) {
    case "vless-reality-vision": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: tcp", "    tls: true", `    servername: ${yaml(s.server_name ?? "")}`, "    flow: xtls-rprx-vision", "    reality-opts:", `      public-key: ${yaml(s.reality_public_key ?? "")}`, `      short-id: ${yaml(s.reality_short_id ?? "")}`, "    client-fingerprint: chrome"];
    case "shadowsocks-aead": return [...lines, "    type: ss", `    cipher: ${yaml(s.shadowsocks_method ?? "")}`, `    password: ${yaml(`${s.shadowsocks_server_password}:${client.shadowsocks_password}`)}`, "    udp: true"];
  }
}

export function mihomoSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return `${["proxies:", ...expand(records).flatMap((node) => mihomoProxy(client, node))].join("\n")}\n`;
}

function uri(client: ClientRecord, node: ExpandedNode): string {
  const s = node.settings;
  let url: URL;
  if (node.type.startsWith("vless-")) {
    url = new URL(`vless://${client.uuid}@${uriHost(node.address)}:${s.listen_port}`);
    url.searchParams.set("encryption", "none");
    if (node.type === "vless-reality-vision") {
      url.searchParams.set("flow", "xtls-rprx-vision"); url.searchParams.set("security", "reality"); url.searchParams.set("sni", s.server_name ?? ""); url.searchParams.set("fp", "chrome"); url.searchParams.set("pbk", s.reality_public_key ?? ""); url.searchParams.set("sid", s.reality_short_id ?? "");
    }
  } else {
    const credential = btoa(`${s.shadowsocks_method}:${s.shadowsocks_server_password}:${client.shadowsocks_password}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    url = new URL(`ss://${credential}@${uriHost(node.address)}:${s.listen_port}`);
  }
  url.hash = tag(node);
  return url.toString();
}

export function uriSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return `${expand(records).map((node) => uri(client, node)).join("\n")}\n`;
}
