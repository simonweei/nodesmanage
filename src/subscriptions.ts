import type { ClientRecord, NodeRecord, ProfileSettings } from "./domain";

interface ExpandedNode extends NodeRecord { settings: ProfileSettings }
const expand = (nodes: NodeRecord[]): ExpandedNode[] => nodes.flatMap((node) => {
  const profiles = node.protocols_json ? JSON.parse(node.protocols_json) as { type: NodeRecord["type"]; settings: ProfileSettings }[] : [{ type: node.type, settings: JSON.parse(node.settings_json) as ProfileSettings }];
  return profiles.map((profile) => ({ ...node, type: profile.type, settings: node.ingress_mode === "cloudflare_tunnel" ? {
    ...profile.settings,
    listen_port: node.connect_port || 443,
    server_address: node.connect_host,
    tls_server_name: node.connect_host,
    websocket_host: node.connect_host,
  } : profile.settings }));
});
const uriHost = (address: string): string => address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
const yaml = (value: string): string => JSON.stringify(value);
const tag = (node: ExpandedNode): string => `${node.name} · ${node.type}`;
const address = (node: ExpandedNode): string => node.settings.server_address || node.connect_host;
const clientTls = (settings: ProfileSettings, alpn?: string[]): Record<string, unknown> => ({
  enabled: true, server_name: settings.tls_server_name,
  ...(alpn ? { alpn } : {}),
  utls: { enabled: true, fingerprint: "chrome" },
});

function singOutbound(client: ClientRecord, node: ExpandedNode): Record<string, unknown> {
  const common = { tag: tag(node), server: address(node), server_port: node.settings.listen_port };
  switch (node.type) {
    case "vless-reality-vision": return { ...common, type: "vless", uuid: client.uuid, flow: "xtls-rprx-vision", tls: { enabled: true, server_name: node.settings.server_name, reality: { enabled: true, public_key: node.settings.reality_public_key, short_id: node.settings.reality_short_id }, utls: { enabled: true, fingerprint: "chrome" } } };
    case "shadowsocks-aead": return { ...common, type: "shadowsocks", method: node.settings.shadowsocks_method, password: `${node.settings.shadowsocks_server_password}:${client.shadowsocks_password}`, multiplex: { enabled: true } };
    case "vless-tls-websocket": return { ...common, type: "vless", uuid: client.uuid, tls: clientTls(node.settings), transport: { type: "ws", path: node.settings.websocket_path, headers: { Host: node.settings.websocket_host } } };
    case "vless-tls-grpc": return { ...common, type: "vless", uuid: client.uuid, tls: clientTls(node.settings, ["h2"]), transport: { type: "grpc", service_name: node.settings.grpc_service_name } };
    case "hysteria2": return { ...common, type: "hysteria2", password: client.shadowsocks_password, obfs: { type: "salamander", password: node.settings.hysteria2_obfs_password }, tls: clientTls(node.settings) };
    case "tuic": return { ...common, type: "tuic", uuid: client.uuid, password: client.shadowsocks_password, congestion_control: "bbr", udp_relay_mode: "native", zero_rtt_handshake: false, tls: clientTls(node.settings) };
    case "trojan-tls": return { ...common, type: "trojan", password: client.shadowsocks_password, tls: clientTls(node.settings), multiplex: { enabled: true } };
  }
}

export function singBoxSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return JSON.stringify({ outbounds: expand(records).map((node) => singOutbound(client, node)) }, null, 2);
}

function mihomoProxy(client: ClientRecord, node: ExpandedNode): string[] {
  const s = node.settings;
  const lines = [`  - name: ${yaml(tag(node))}`, `    server: ${yaml(address(node))}`, `    port: ${s.listen_port}`];
  switch (node.type) {
    case "vless-reality-vision": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: tcp", "    tls: true", `    servername: ${yaml(s.server_name ?? "")}`, "    flow: xtls-rprx-vision", "    reality-opts:", `      public-key: ${yaml(s.reality_public_key ?? "")}`, `      short-id: ${yaml(s.reality_short_id ?? "")}`, "    client-fingerprint: chrome"];
    case "shadowsocks-aead": return [...lines, "    type: ss", `    cipher: ${yaml(s.shadowsocks_method ?? "")}`, `    password: ${yaml(`${s.shadowsocks_server_password}:${client.shadowsocks_password}`)}`, "    udp: true"];
    case "vless-tls-websocket": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: ws", "    tls: true", `    servername: ${yaml(s.tls_server_name ?? "")}`, "    client-fingerprint: chrome", "    ws-opts:", `      path: ${yaml(s.websocket_path ?? "/")}`, "      headers:", `        Host: ${yaml(s.websocket_host ?? "")}`];
    case "vless-tls-grpc": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: grpc", "    tls: true", `    servername: ${yaml(s.tls_server_name ?? "")}`, "    client-fingerprint: chrome", "    grpc-opts:", `      grpc-service-name: ${yaml(s.grpc_service_name ?? "")}`];
    case "hysteria2": return [...lines, "    type: hysteria2", `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    obfs: salamander", `    obfs-password: ${yaml(s.hysteria2_obfs_password ?? "")}`];
    case "tuic": return [...lines, "    type: tuic", `    uuid: ${yaml(client.uuid)}`, `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    congestion-controller: bbr", "    udp-relay-mode: native", "    udp: true"];
    case "trojan-tls": return [...lines, "    type: trojan", `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    udp: true"];
  }
}

export function mihomoSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return `${["proxies:", ...expand(records).flatMap((node) => mihomoProxy(client, node))].join("\n")}\n`;
}

function uri(client: ClientRecord, node: ExpandedNode): string {
  const s = node.settings;
  const host = uriHost(address(node));
  let url: URL;
  if (node.type.startsWith("vless-")) {
    url = new URL(`vless://${client.uuid}@${host}:${s.listen_port}`);
    url.searchParams.set("encryption", "none");
    if (node.type === "vless-reality-vision") {
      url.searchParams.set("flow", "xtls-rprx-vision"); url.searchParams.set("security", "reality"); url.searchParams.set("sni", s.server_name ?? ""); url.searchParams.set("fp", "chrome"); url.searchParams.set("pbk", s.reality_public_key ?? ""); url.searchParams.set("sid", s.reality_short_id ?? "");
    } else if (node.type === "vless-tls-websocket") {
      url.searchParams.set("security", "tls"); url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("fp", "chrome"); url.searchParams.set("type", "ws"); url.searchParams.set("host", s.websocket_host ?? ""); url.searchParams.set("path", s.websocket_path ?? "/");
    } else if (node.type === "vless-tls-grpc") {
      url.searchParams.set("security", "tls"); url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("fp", "chrome"); url.searchParams.set("type", "grpc"); url.searchParams.set("serviceName", s.grpc_service_name ?? "");
    }
  } else if (node.type === "shadowsocks-aead") {
    const credential = btoa(`${s.shadowsocks_method}:${s.shadowsocks_server_password}:${client.shadowsocks_password}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    url = new URL(`ss://${credential}@${host}:${s.listen_port}`);
  } else if (node.type === "hysteria2") {
    url = new URL(`hysteria2://${encodeURIComponent(client.shadowsocks_password)}@${host}:${s.listen_port}`);
    url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("obfs", "salamander"); url.searchParams.set("obfs-password", s.hysteria2_obfs_password ?? "");
  } else if (node.type === "tuic") {
    url = new URL(`tuic://${client.uuid}:${encodeURIComponent(client.shadowsocks_password)}@${host}:${s.listen_port}`);
    url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("congestion_control", "bbr"); url.searchParams.set("udp_relay_mode", "native");
  } else {
    url = new URL(`trojan://${encodeURIComponent(client.shadowsocks_password)}@${host}:${s.listen_port}`);
    url.searchParams.set("security", "tls"); url.searchParams.set("sni", s.tls_server_name ?? "");
  }
  url.hash = tag(node);
  return url.toString();
}

export function uriSubscription(client: ClientRecord, records: NodeRecord[]): string {
  return `${expand(records).map((node) => uri(client, node)).join("\n")}\n`;
}
