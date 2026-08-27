import type { ClientRecord, NodeRecord, ProfileSettings } from "./domain";

interface ExpandedNode extends NodeRecord { settings: ProfileSettings }
const expand = (nodes: NodeRecord[]): ExpandedNode[] => nodes.flatMap((node) => {
  const profiles = node.protocols_json ? JSON.parse(node.protocols_json) as { type: NodeRecord["type"]; settings: ProfileSettings }[] : [{ type: node.type, settings: JSON.parse(node.settings_json) as ProfileSettings }];
  return profiles.map((profile) => ({ ...node, type: profile.type, settings: profile.settings }));
});
const uriHost = (address: string): string => address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
const yaml = (value: string): string => JSON.stringify(value);
const tag = (node: ExpandedNode): string => `${node.name} · ${node.type}`;

function tlsClient(settings: ProfileSettings): Record<string, unknown> {
  return { enabled: true, server_name: settings.server_name };
}

function singOutbound(client: ClientRecord, node: ExpandedNode): Record<string, unknown> {
  const common = { tag: tag(node), server: node.address, server_port: node.settings.listen_port };
  switch (node.type) {
    case "vless-reality-vision": return { ...common, type: "vless", uuid: client.uuid, flow: "xtls-rprx-vision", tls: { enabled: true, server_name: node.settings.server_name, reality: { enabled: true, public_key: node.settings.reality_public_key, short_id: node.settings.reality_short_id }, utls: { enabled: true, fingerprint: "chrome" } } };
    case "vless-tls-ws": return { ...common, type: "vless", uuid: client.uuid, tls: tlsClient(node.settings), transport: { type: "ws", path: node.settings.ws_path, headers: { Host: node.settings.ws_host } } };
    case "vless-tls-grpc": return { ...common, type: "vless", uuid: client.uuid, tls: tlsClient(node.settings), transport: { type: "grpc", service_name: node.settings.grpc_service_name } };
    case "trojan-tls": return { ...common, type: "trojan", password: client.trojan_password, tls: tlsClient(node.settings) };
    case "hysteria2-tls": return { ...common, type: "hysteria2", password: client.hysteria2_password, tls: tlsClient(node.settings) };
    case "hysteria2-tls-obfs": return { ...common, type: "hysteria2", password: client.hysteria2_password, obfs: { type: "salamander", password: node.settings.hysteria2_obfs_password }, tls: tlsClient(node.settings) };
    case "tuic-tls": return { ...common, type: "tuic", uuid: client.uuid, password: client.tuic_password, congestion_control: node.settings.tuic_congestion_control, zero_rtt_handshake: false, tls: tlsClient(node.settings) };
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
    case "vless-tls-ws": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: ws", "    tls: true", `    servername: ${yaml(s.server_name ?? "")}`, "    ws-opts:", `      path: ${yaml(s.ws_path ?? "/")}`, "      headers:", `        Host: ${yaml(s.ws_host ?? "")}`];
    case "vless-tls-grpc": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: grpc", "    tls: true", `    servername: ${yaml(s.server_name ?? "")}`, "    grpc-opts:", `      grpc-service-name: ${yaml(s.grpc_service_name ?? "")}`];
    case "trojan-tls": return [...lines, "    type: trojan", `    password: ${yaml(client.trojan_password)}`, `    sni: ${yaml(s.server_name ?? "")}`];
    case "hysteria2-tls": return [...lines, "    type: hysteria2", `    password: ${yaml(client.hysteria2_password)}`, `    sni: ${yaml(s.server_name ?? "")}`];
    case "hysteria2-tls-obfs": return [...lines, "    type: hysteria2", `    password: ${yaml(client.hysteria2_password)}`, `    sni: ${yaml(s.server_name ?? "")}`, "    obfs: salamander", `    obfs-password: ${yaml(s.hysteria2_obfs_password ?? "")}`];
    case "tuic-tls": return [...lines, "    type: tuic", `    uuid: ${yaml(client.uuid)}`, `    password: ${yaml(client.tuic_password)}`, `    sni: ${yaml(s.server_name ?? "")}`, `    congestion-controller: ${yaml(s.tuic_congestion_control ?? "cubic")}`, "    reduce-rtt: false"];
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
    } else {
      url.searchParams.set("security", "tls"); url.searchParams.set("sni", s.server_name ?? "");
      if (node.type === "vless-tls-ws") { url.searchParams.set("type", "ws"); url.searchParams.set("path", s.ws_path ?? "/"); url.searchParams.set("host", s.ws_host ?? ""); }
      else { url.searchParams.set("type", "grpc"); url.searchParams.set("serviceName", s.grpc_service_name ?? ""); }
    }
  } else if (node.type === "trojan-tls") {
    url = new URL(`trojan://${encodeURIComponent(client.trojan_password)}@${uriHost(node.address)}:${s.listen_port}`); url.searchParams.set("sni", s.server_name ?? "");
  } else if (node.type.startsWith("hysteria2-")) {
    url = new URL(`hysteria2://${encodeURIComponent(client.hysteria2_password)}@${uriHost(node.address)}:${s.listen_port}`); url.searchParams.set("sni", s.server_name ?? "");
    if (node.type.endsWith("obfs")) { url.searchParams.set("obfs", "salamander"); url.searchParams.set("obfs-password", s.hysteria2_obfs_password ?? ""); }
  } else if (node.type === "tuic-tls") {
    url = new URL(`tuic://${client.uuid}:${encodeURIComponent(client.tuic_password)}@${uriHost(node.address)}:${s.listen_port}`); url.searchParams.set("sni", s.server_name ?? ""); url.searchParams.set("congestion_control", s.tuic_congestion_control ?? "cubic");
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
