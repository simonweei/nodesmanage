const state = { agents: [], profiles: [], clients: [], nodes: [], enrollment_codes: [], subscriptions: [] };
const $ = (selector) => document.querySelector(selector);
const headers = { "content-type": "application/json", "x-admin-email": "local@nodemanage.invalid" };
const profileCatalog = [
  ["vless-reality-vision", "VLESS · Reality + Vision", "★★★★★", "首选：无需证书，密钥与 Short ID 自动生成"],
  ["vless-tls-ws", "VLESS · TLS + WebSocket", "★★★★★", "兼容性高，需要已有 TLS 证书"],
  ["vless-tls-grpc", "VLESS · TLS + gRPC", "★★★★", "多路复用，需要已有 TLS 证书"],
  ["trojan-tls", "Trojan · TLS", "★★★★", "简单稳定，需要已有 TLS 证书"],
  ["hysteria2-tls", "Hysteria2 · TLS", "★★★★★", "UDP/QUIC，高延迟线路优先"],
  ["hysteria2-tls-obfs", "Hysteria2 · TLS + Salamander", "★★★★★", "增加固定混淆层，密码自动生成"],
  ["tuic-tls", "TUIC · TLS", "★★★★", "UDP/QUIC，默认关闭 0-RTT"],
  ["shadowsocks-aead", "Shadowsocks · AEAD 2022", "★★★★", "多用户 AES-128-GCM，凭据自动生成"],
];
let profileDefaults = {};

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

function notice(message, error = false) {
  const element = $("#notice");
  element.textContent = message;
  element.style.color = error ? "#ff8b8b" : "#72f1b8";
}

function textElement(tag, text, className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function formatBytes(value) {
  if (!value) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Number(value), index = 0;
  while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
  return `${number.toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
}

function fact(parent, label, value) {
  const box = document.createElement("div");
  box.append(textElement("span", label), document.createTextNode(value));
  parent.append(box);
}

function renderAgents() {
  const root = $("#agents"); root.replaceChildren();
  $("#agent-count").textContent = String(state.agents.length);
  for (const agent of state.agents) {
    const card = textElement("article", "", "card");
    const head = textElement("div", "", "card-head");
    const title = textElement("strong", agent.name);
    const online = agent.last_seen && Date.now() - Date.parse(`${agent.last_seen}Z`) < 150000;
    head.append(title, textElement("span", online ? "在线" : "离线", online ? "online" : "offline"));
    const facts = textElement("div", "", "facts");
    fact(facts, "地址", agent.public_ip || "—");
    fact(facts, "系统", `${agent.os}/${agent.architecture}`);
    fact(facts, "sing-box", agent.singbox_version || "未上报");
    fact(facts, "配置版本", `${agent.current_revision || "—"} → ${agent.desired_revision || "—"}`);
    fact(facts, "内存", `${formatBytes(agent.memory_used_bytes)} / ${formatBytes(agent.memory_total_bytes)}`);
    fact(facts, "磁盘", `${formatBytes(agent.disk_used_bytes)} / ${formatBytes(agent.disk_total_bytes)}`);
    const permissions = textElement("pre", agent.permissions_json || "{}", "permissions");
    const publish = textElement("button", "发布当前 Profile");
    publish.addEventListener("click", () => action(`/api/admin/agents/${agent.id}/publish`, {}));
    card.append(head, facts, permissions, publish);
    if (agent.last_error) card.append(textElement("p", agent.last_error, "offline"));
    root.append(card);
  }
  if (!state.agents.length) root.append(textElement("div", "尚未注册 Agent", "panel muted"));
}

function setOptions(selector, values, label) {
  const select = $(selector); select.replaceChildren();
  for (const value of values) {
    const option = document.createElement("option"); option.value = value.id; option.textContent = label(value); select.append(option);
  }
}

function renderLists() {
  const clients = $("#clients"); clients.replaceChildren();
  state.clients.forEach((client) => { const row = document.createElement("div"); row.append(textElement("span", client.name), textElement("code", client.uuid)); clients.append(row); });
  const profiles = $("#profiles"); profiles.replaceChildren();
  state.profiles.forEach((profile) => { const row = document.createElement("div"); row.append(textElement("span", profile.name), textElement("code", profile.type)); profiles.append(row); });
  renderToggleList("#codes", state.enrollment_codes, "enrollment-codes", (value) => `${value.name} · 已使用 ${value.use_count}${value.max_uses ? `/${value.max_uses}` : " 次"}`);
  renderToggleList("#subscriptions", state.subscriptions, "subscriptions", (value) => `${value.name} · ${value.client_name}`);
  setOptions("#node-agent", state.agents, (value) => value.name);
  setOptions("#node-profile", state.profiles, (value) => `${value.name} · ${value.type}`);
  setOptions("#subscription-client", state.clients, (value) => value.name);
}

function renderToggleList(selector, values, resource, label) {
  const root = $(selector); root.replaceChildren();
  for (const value of values) {
    const row = document.createElement("div");
    const button = textElement("button", value.enabled ? "停用" : "启用", "secondary");
    button.addEventListener("click", () => action(`/api/admin/${resource}/${value.id}/enabled`, { enabled: !Boolean(value.enabled) }));
    row.append(textElement("span", label(value)), button); root.append(row);
  }
}

async function load() {
  try {
    Object.assign(state, await api("/api/admin/state"));
    renderAgents(); renderLists(); notice("数据已刷新");
  } catch (error) { notice(error.message, true); }
}

async function action(path, body) {
  try { await api(path, { method: "POST", body: JSON.stringify(body) }); notice("操作成功"); await load(); }
  catch (error) { notice(error.message, true); }
}

function formObject(form) { return Object.fromEntries(new FormData(form).entries()); }

$("#code-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const values = formObject(event.currentTarget);
  const body = { name: values.name }; if (values.max_uses) body.max_uses = Number(values.max_uses);
  try { const result = await api("/api/admin/enrollment-codes", { method: "POST", body: JSON.stringify(body) }); $("#install-command").textContent = `curl -fsSL ${location.origin}/install.sh | sudo sh -s -- --code ${result.code}`; await load(); }
  catch (error) { notice(error.message, true); }
});

$("#client-form").addEventListener("submit", (event) => { event.preventDefault(); action("/api/admin/clients", formObject(event.currentTarget)); });
$("#node-form").addEventListener("submit", (event) => { event.preventDefault(); action("/api/admin/nodes", formObject(event.currentTarget)); });
$("#profile-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const values = formObject(event.currentTarget), settings = {};
  document.querySelectorAll("#profile-fields [data-setting]").forEach((field) => { settings[field.name] = field.type === "number" ? Number(field.value) : field.value; });
  action("/api/admin/profiles", { name: values.name, type: values.type, settings });
});
$("#subscription-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try { const result = await api("/api/admin/subscriptions", { method: "POST", body: JSON.stringify(formObject(event.currentTarget)) }); $("#subscription-links").textContent = [`${location.origin}/sub/${result.token}/sing-box`, `${location.origin}/sub/${result.token}/mihomo`, `${location.origin}/sub/${result.token}/uri`].join("\n"); await load(); }
  catch (error) { notice(error.message, true); }
});
function profileField(label, name, value, options = {}) {
  const wrapper = document.createElement("label"); wrapper.append(document.createTextNode(label));
  let field;
  if (options.choices) {
    field = document.createElement("select");
    options.choices.forEach(([key, text]) => { const option = document.createElement("option"); option.value = key; option.textContent = text; field.append(option); });
  } else {
    field = document.createElement("input"); field.type = options.type || "text";
  }
  field.name = name; field.value = value ?? ""; field.dataset.setting = ""; field.required = true;
  if (options.readonly) { field.readOnly = true; wrapper.classList.add("auto-field"); }
  wrapper.append(field); return wrapper;
}

async function renderProfileFields() {
  const type = $("#profile-type").value;
  const selected = profileCatalog.find(([key]) => key === type);
  $("#profile-priority").textContent = `${selected[2]} · ${selected[3]}`;
  const result = await api(`/api/admin/profile-defaults?type=${encodeURIComponent(type)}`);
  if ($("#profile-type").value !== type) return;
  profileDefaults = result.settings;
  const root = $("#profile-fields"); root.replaceChildren();
  root.append(profileField("端口", "listen_port", profileDefaults.listen_port, { type: "number" }));
  if (type === "vless-reality-vision") {
    const target = profileField("Reality 目标", "reality_target", profileDefaults.reality_handshake_server, { choices: [["www.microsoft.com", "Microsoft · 推荐"], ["www.apple.com", "Apple"], ["www.cloudflare.com", "Cloudflare"], ["custom", "自定义"]] });
    const select = target.querySelector("select");
    select.removeAttribute("data-setting");
    const handshake = document.createElement("input"); handshake.type = "hidden"; handshake.name = "reality_handshake_server"; handshake.value = profileDefaults.reality_handshake_server; handshake.dataset.setting = "";
    const custom = profileField("自定义目标", "reality_custom", ""); custom.style.display = "none"; custom.querySelector("input").removeAttribute("data-setting");
    select.addEventListener("change", () => {
      const isCustom = select.value === "custom"; custom.style.display = isCustom ? "grid" : "none";
      if (!isCustom) { handshake.value = select.value; root.querySelector("[name=server_name]").value = select.value; }
    });
    custom.querySelector("input").addEventListener("input", (event) => { handshake.value = event.target.value; root.querySelector("[name=server_name]").value = event.target.value; });
    root.append(target, custom, handshake, profileField("Server Name · 自动", "server_name", profileDefaults.server_name, { readonly: true }), profileField("Flow · 固定", "flow_display", "xtls-rprx-vision", { readonly: true }), profileField("Private Key · 自动", "reality_private_key", profileDefaults.reality_private_key, { readonly: true }), profileField("Public Key · 自动", "reality_public_key", profileDefaults.reality_public_key, { readonly: true }), profileField("Short ID · 自动", "reality_short_id", profileDefaults.reality_short_id, { readonly: true }), profileField("握手端口", "reality_handshake_port", 443, { type: "number" }));
    root.querySelector("[name=flow_display]").removeAttribute("data-setting");
  } else if (type === "shadowsocks-aead") {
    root.append(profileField("加密方式 · 固定", "shadowsocks_method", profileDefaults.shadowsocks_method, { readonly: true }), profileField("服务器主密码 · 自动", "shadowsocks_server_password", profileDefaults.shadowsocks_server_password, { readonly: true }));
  } else {
    root.append(profileField("Server Name / SNI", "server_name", profileDefaults.server_name), profileField("证书路径", "certificate_path", profileDefaults.certificate_path), profileField("私钥路径", "key_path", profileDefaults.key_path));
    if (type === "vless-tls-ws") root.append(profileField("WebSocket 路径", "ws_path", profileDefaults.ws_path), profileField("WebSocket Host", "ws_host", profileDefaults.ws_host));
    if (type === "vless-tls-grpc") root.append(profileField("gRPC Service Name", "grpc_service_name", profileDefaults.grpc_service_name));
    if (type === "hysteria2-tls-obfs") root.append(profileField("Salamander 密码 · 自动", "hysteria2_obfs_password", profileDefaults.hysteria2_obfs_password, { readonly: true }));
    if (type === "tuic-tls") root.append(profileField("拥塞控制", "tuic_congestion_control", profileDefaults.tuic_congestion_control, { choices: [["cubic", "CUBIC · 推荐"], ["bbr", "BBR"], ["new_reno", "New Reno"]] }));
  }
}

for (const [value, label] of profileCatalog) { const option = document.createElement("option"); option.value = value; option.textContent = label; $("#profile-type").append(option); }
$("#profile-type").addEventListener("change", renderProfileFields);
$("#regenerate-profile").addEventListener("click", renderProfileFields);
$("#refresh").addEventListener("click", load);
renderProfileFields();
load();
