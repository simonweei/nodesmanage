import type { ClientRecord, NodeRecord, ProfileSettings } from "./domain";
import { realityPublicKey } from "./crypto";

interface ExpandedNode extends NodeRecord { settings: ProfileSettings }
const expand = (nodes: NodeRecord[]): ExpandedNode[] => nodes.flatMap((node) => {
  const profiles = node.protocols_json ? JSON.parse(node.protocols_json) as { type: NodeRecord["type"]; settings: ProfileSettings }[] : [{ type: node.type, settings: JSON.parse(node.settings_json) as ProfileSettings }];
  return profiles.map((profile) => {
    let settings = profile.settings;
    if (profile.type === "vless-reality-vision" && settings.reality_private_key) {
      try {
        settings = { ...settings, reality_public_key: realityPublicKey(settings.reality_private_key) };
      } catch {
        // Keep the stored public key for legacy rows whose private key is not decodable.
      }
    }
    return { ...node, type: profile.type, settings: node.ingress_mode === "cloudflare_tunnel" ? {
      ...settings,
      listen_port: profile.settings.edge_port || node.connect_port || 443,
      server_address: node.connect_host,
      tls_server_name: node.connect_host,
      websocket_host: node.connect_host,
    } : node.node_kind === "minimal" ? {
      ...settings,
      listen_port: node.connect_port || settings.listen_port,
    } : settings };
  });
});
const uriHost = (address: string): string => address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
const yaml = (value: string): string => JSON.stringify(value);
const tag = (node: ExpandedNode): string => `${node.name} · ${node.type}`;
const address = (node: ExpandedNode): string => node.settings.server_address || node.connect_host;
const clientForNode = (client: ClientRecord, node: ExpandedNode): ClientRecord =>
  node.node_kind === "minimal" && node.settings.shared_uuid ? { ...client, uuid: node.settings.shared_uuid } : client;
const clientTls = (settings: ProfileSettings, alpn?: string[], useUtls = true): Record<string, unknown> => ({
  enabled: true, server_name: settings.tls_server_name,
  ...(alpn ? { alpn } : {}),
  ...(useUtls ? { utls: { enabled: true, fingerprint: "chrome" } } : {}),
});

function singOutbound(client: ClientRecord, node: ExpandedNode): Record<string, unknown> {
  client = clientForNode(client, node);
  const common = { tag: tag(node), server: address(node), server_port: node.settings.listen_port };
  switch (node.type) {
    case "vless-reality-vision": return { ...common, type: "vless", uuid: client.uuid, flow: "xtls-rprx-vision", tls: { enabled: true, server_name: node.settings.server_name, reality: { enabled: true, public_key: node.settings.reality_public_key, short_id: node.settings.reality_short_id }, utls: { enabled: true, fingerprint: "chrome" } } };
    case "shadowsocks-aead": return { ...common, type: "shadowsocks", method: node.settings.shadowsocks_method, password: `${node.settings.shadowsocks_server_password}:${client.shadowsocks_password}`, multiplex: { enabled: true } };
    case "vless-tls-websocket": return { ...common, type: "vless", uuid: client.uuid, tls: clientTls(node.settings), transport: { type: "ws", path: node.settings.websocket_path, headers: { Host: node.settings.websocket_host } } };
    case "vless-tls-grpc": return { ...common, type: "vless", uuid: client.uuid, tls: clientTls(node.settings, ["h2"]), transport: { type: "grpc", service_name: node.settings.grpc_service_name } };
    case "hysteria2": return { ...common, type: "hysteria2", password: client.shadowsocks_password, obfs: { type: "salamander", password: node.settings.hysteria2_obfs_password }, tls: clientTls(node.settings, undefined, false) };
    case "tuic": return { ...common, type: "tuic", uuid: client.uuid, password: client.shadowsocks_password, congestion_control: "bbr", udp_relay_mode: "native", zero_rtt_handshake: false, heartbeat: "10s", tls: clientTls(node.settings, ["h3"], false) };
    case "trojan-tls": return { ...common, type: "trojan", password: client.shadowsocks_password, tls: clientTls(node.settings), multiplex: { enabled: true } };
    case "trojan-tls-websocket": return { ...common, type: "trojan", password: client.shadowsocks_password, tls: clientTls(node.settings), transport: { type: "ws", path: node.settings.websocket_path, headers: { Host: node.settings.websocket_host } } };
  }
}

export function singBoxSubscription(client: ClientRecord, records: NodeRecord[]): string {
  const proxyOutbounds = expand(records).map((node) => singOutbound(client, node));
  if (!proxyOutbounds.length) return JSON.stringify({ outbounds: [] }, null, 2);

  const selectorTag = "节点选择";
  const directTag = "direct";
  const localDnsTag = "local-dns";
  const fakeIpDnsTag = "fakeip-dns";
  const chinaSiteRuleSetTag = "geosite-cn";
  const chinaIpRuleSetTag = "geoip-cn";
  const ruleSetHttpClientTag = "rule-set-http";
  const proxyTags = proxyOutbounds.map((outbound) => String(outbound.tag));
  return JSON.stringify({
    http_clients: [{
      tag: ruleSetHttpClientTag,
      engine: "go",
      detour: selectorTag,
    }],
    dns: {
      servers: [
        { type: "tls", tag: "proxy-dns", server: "8.8.8.8" },
        { type: "udp", tag: localDnsTag, server: "223.5.5.5" },
        { type: "fakeip", tag: fakeIpDnsTag, inet4_range: "198.18.0.0/15", inet6_range: "fc00::/18" },
      ],
      rules: [
        { rule_set: chinaSiteRuleSetTag, action: "route", server: localDnsTag },
        { query_type: ["A", "AAAA"], action: "route", server: fakeIpDnsTag },
      ],
    },
    inbounds: [{
      type: "tun",
      tag: "tun-in",
      address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      auto_route: true,
      strict_route: true,
    }],
    outbounds: [
      ...proxyOutbounds,
      {
        type: "selector",
        tag: selectorTag,
        outbounds: proxyTags,
        default: proxyTags[0],
        interrupt_exist_connections: true,
      },
      { type: "direct", tag: directTag },
    ],
    route: {
      rules: [
        { action: "sniff" },
        { protocol: "dns", action: "hijack-dns" },
        { ip_is_private: true, action: "route", outbound: directTag },
        { rule_set: chinaSiteRuleSetTag, action: "route", outbound: directTag },
        { rule_set: chinaIpRuleSetTag, action: "route", outbound: directTag },
      ],
      rule_set: [
        {
          type: "remote",
          tag: chinaSiteRuleSetTag,
          format: "binary",
          url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs",
          update_interval: "1d",
        },
        {
          type: "remote",
          tag: chinaIpRuleSetTag,
          format: "binary",
          url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
          update_interval: "1d",
        },
      ],
      final: selectorTag,
      default_http_client: ruleSetHttpClientTag,
      default_domain_resolver: localDnsTag,
      auto_detect_interface: true,
    },
    experimental: { cache_file: { enabled: true } },
  }, null, 2);
}

export function shadowsocksSubscription(client: ClientRecord, records: NodeRecord[]): string {
  const servers = expand(records)
    .filter((node) => node.type === "shadowsocks-aead")
    .map((node) => ({
      id: node.id,
      remarks: tag(node),
      server: address(node),
      server_port: node.settings.listen_port,
      password: `${node.settings.shadowsocks_server_password}:${client.shadowsocks_password}`,
      method: node.settings.shadowsocks_method,
    }));
  return JSON.stringify({ version: 1, servers }, null, 2);
}

function mihomoProxy(client: ClientRecord, node: ExpandedNode): string[] {
  client = clientForNode(client, node);
  const s = node.settings;
  const lines = [`  - name: ${yaml(tag(node))}`, `    server: ${yaml(address(node))}`, `    port: ${s.listen_port}`];
  switch (node.type) {
    case "vless-reality-vision": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: tcp", "    udp: true", "    packet-encoding: xudp", `    encryption: ${yaml("")}`, "    tls: true", `    servername: ${yaml(s.server_name ?? "")}`, "    flow: xtls-rprx-vision", "    reality-opts:", `      public-key: ${yaml(s.reality_public_key ?? "")}`, `      short-id: ${yaml(s.reality_short_id ?? "")}`, "    client-fingerprint: chrome"];
    case "shadowsocks-aead": return [...lines, "    type: ss", `    cipher: ${yaml(s.shadowsocks_method ?? "")}`, `    password: ${yaml(`${s.shadowsocks_server_password}:${client.shadowsocks_password}`)}`, "    udp: true"];
    case "vless-tls-websocket": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: ws", "    tls: true", `    servername: ${yaml(s.tls_server_name ?? "")}`, "    client-fingerprint: chrome", "    ws-opts:", `      path: ${yaml(s.websocket_path ?? "/")}`, "      headers:", `        Host: ${yaml(s.websocket_host ?? "")}`];
    case "vless-tls-grpc": return [...lines, "    type: vless", `    uuid: ${yaml(client.uuid)}`, "    network: grpc", "    tls: true", `    servername: ${yaml(s.tls_server_name ?? "")}`, "    client-fingerprint: chrome", "    grpc-opts:", `      grpc-service-name: ${yaml(s.grpc_service_name ?? "")}`];
    case "hysteria2": return [...lines, "    type: hysteria2", `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    obfs: salamander", `    obfs-password: ${yaml(s.hysteria2_obfs_password ?? "")}`];
    case "tuic": return [...lines, "    type: tuic", `    uuid: ${yaml(client.uuid)}`, `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    alpn:", "      - h3", "    skip-cert-verify: false", "    congestion-controller: bbr", "    udp-relay-mode: native", "    heartbeat-interval: 10000", "    request-timeout: 8000", "    reduce-rtt: false", "    udp: true"];
    case "trojan-tls": return [...lines, "    type: trojan", `    password: ${yaml(client.shadowsocks_password)}`, `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    udp: true"];
    case "trojan-tls-websocket": return [...lines, "    type: trojan", `    password: ${yaml(client.shadowsocks_password)}`, "    network: ws", "    tls: true", `    sni: ${yaml(s.tls_server_name ?? "")}`, "    skip-cert-verify: false", "    ws-opts:", `      path: ${yaml(s.websocket_path ?? "/")}`, "      headers:", `        Host: ${yaml(s.websocket_host ?? "")}`];
  }
}

export function mihomoSubscription(client: ClientRecord, records: NodeRecord[]): string {
  const nodes = expand(records);
  const proxyNames = nodes.map((node) => tag(node));
  return `${[
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "ipv6: true",
    "proxies:",
    ...nodes.flatMap((node) => mihomoProxy(client, node)),
    "proxy-groups:",
    "  - name: 节点选择",
    "    type: select",
    "    proxies:",
    ...proxyNames.map((name) => `      - ${yaml(name)}`),
    "rules:",
    "  - MATCH,节点选择",
  ].join("\n")}\n`;
}

function uri(client: ClientRecord, node: ExpandedNode): string {
  client = clientForNode(client, node);
  const s = node.settings;
  const host = uriHost(address(node));
  let url: URL;
  if (node.type.startsWith("vless-")) {
    url = new URL(`vless://${client.uuid}@${host}:${s.listen_port}`);
    url.searchParams.set("encryption", "none");
    if (node.type === "vless-reality-vision") {
      url.searchParams.set("flow", "xtls-rprx-vision"); url.searchParams.set("security", "reality"); url.searchParams.set("sni", s.server_name ?? ""); url.searchParams.set("fp", "chrome"); url.searchParams.set("pbk", s.reality_public_key ?? ""); url.searchParams.set("sid", s.reality_short_id ?? ""); url.searchParams.set("type", "tcp"); url.searchParams.set("headerType", "none");
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
    url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("alpn", "h3"); url.searchParams.set("congestion_control", "bbr"); url.searchParams.set("udp_relay_mode", "native"); url.searchParams.set("zero_rtt_handshake", "0");
  } else if (node.type === "trojan-tls-websocket") {
    url = new URL(`trojan://${encodeURIComponent(client.shadowsocks_password)}@${host}:${s.listen_port}`);
    url.searchParams.set("security", "tls"); url.searchParams.set("sni", s.tls_server_name ?? ""); url.searchParams.set("type", "ws"); url.searchParams.set("host", s.websocket_host ?? ""); url.searchParams.set("path", s.websocket_path ?? "/");
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

export function v2rayNSubscription(client: ClientRecord, records: NodeRecord[]): string {
  const bytes = new TextEncoder().encode(uriSubscription(client, records));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
