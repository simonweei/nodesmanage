PRAGMA foreign_keys = ON;

CREATE TABLE profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('vless-reality-vision', 'shadowsocks-aead', 'vless-tls-websocket', 'vless-tls-grpc', 'hysteria2', 'tuic', 'trojan-tls')),
  settings_json TEXT NOT NULL,
  protocols_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  os TEXT NOT NULL,
  distro TEXT NOT NULL DEFAULT '',
  distro_version TEXT NOT NULL DEFAULT '',
  architecture TEXT NOT NULL,
  libc TEXT NOT NULL DEFAULT '',
  init_system TEXT NOT NULL DEFAULT '',
  install_mode TEXT NOT NULL CHECK (install_mode IN ('system', 'user')),
  agent_version TEXT,
  singbox_version TEXT,
  cloudflared_version TEXT,
  observed_egress_ip TEXT NOT NULL DEFAULT '',
  current_revision INTEGER,
  desired_revision INTEGER,
  singbox_running INTEGER NOT NULL DEFAULT 0 CHECK (singbox_running IN (0, 1)),
  tunnel_running INTEGER NOT NULL DEFAULT 0 CHECK (tunnel_running IN (0, 1)),
  tunnel_hostname TEXT NOT NULL DEFAULT '',
  tunnel_error TEXT,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  cpu_usage_percent REAL CHECK (cpu_usage_percent IS NULL OR (cpu_usage_percent >= 0 AND cpu_usage_percent <= 100)),
  uptime_seconds INTEGER CHECK (uptime_seconds IS NULL OR uptime_seconds >= 0),
  memory_total_bytes INTEGER CHECK (memory_total_bytes IS NULL OR memory_total_bytes >= 0),
  memory_used_bytes INTEGER CHECK (memory_used_bytes IS NULL OR memory_used_bytes >= 0),
  disk_total_bytes INTEGER CHECK (disk_total_bytes IS NULL OR disk_total_bytes >= 0),
  disk_used_bytes INTEGER CHECK (disk_used_bytes IS NULL OR disk_used_bytes >= 0),
  permissions_json TEXT NOT NULL DEFAULT '{}',
  last_error TEXT,
  last_seen TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (current_revision) REFERENCES revisions(id),
  FOREIGN KEY (desired_revision) REFERENCES revisions(id)
);

CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  agent_id TEXT UNIQUE,
  profile_id TEXT NOT NULL,
  name TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  node_kind TEXT NOT NULL DEFAULT 'managed' CHECK (node_kind IN ('managed', 'minimal')),
  ingress_mode TEXT NOT NULL DEFAULT 'direct' CHECK (ingress_mode IN ('direct', 'cloudflare_tunnel')),
  tunnel_kind TEXT NOT NULL DEFAULT 'none' CHECK (tunnel_kind IN ('none', 'quick', 'named')),
  connect_host TEXT NOT NULL DEFAULT '',
  connect_port INTEGER NOT NULL DEFAULT 0 CHECK (connect_port BETWEEN 0 AND 65535),
  origin_port INTEGER NOT NULL DEFAULT 0 CHECK (origin_port BETWEEN 0 AND 65535),
  edge_tls INTEGER NOT NULL DEFAULT 0 CHECK (edge_tls IN (0, 1)),
  ingress_status TEXT NOT NULL DEFAULT 'pending' CHECK (ingress_status IN ('pending', 'configured', 'connected', 'verified', 'failed')),
  ingress_verified_at TEXT,
  last_ingress_error TEXT,
  deployment_mode TEXT NOT NULL DEFAULT 'system' CHECK (deployment_mode IN ('system', 'user')),
  deployment_policy TEXT NOT NULL DEFAULT 'system' CHECK (deployment_policy IN ('auto', 'system', 'user')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  draft INTEGER NOT NULL DEFAULT 0 CHECK (draft IN (0, 1)),
  retiring INTEGER NOT NULL DEFAULT 0 CHECK (retiring IN (0, 1)),
  install_stage TEXT NOT NULL DEFAULT 'ticket_created' CHECK (install_stage IN (
    'ticket_created', 'bootstrap_started', 'agent_downloaded', 'runtime_downloaded', 'tunnel_downloaded',
    'runtime_installed', 'service_installed', 'registered', 'online', 'upgrading', 'upgraded', 'failed'
  )),
  last_install_error_code TEXT,
  last_install_message TEXT,
  last_install_source TEXT,
  last_install_at TEXT,
  provisioned_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
  FOREIGN KEY (profile_id) REFERENCES profiles(id)
);

CREATE TABLE clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  uuid TEXT NOT NULL UNIQUE,
  shadowsocks_password TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE subscription_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE subscriptions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  group_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_value TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (group_id) REFERENCES subscription_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE subscription_group_nodes (
  group_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  PRIMARY KEY (group_id, node_id),
  FOREIGN KEY (group_id) REFERENCES subscription_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  profile_id TEXT,
  config_json TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
  FOREIGN KEY (profile_id) REFERENCES profiles(id)
);

CREATE TABLE install_tickets (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  agent_id TEXT,
  claim_hash TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE install_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id TEXT NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN (
    'ticket_created', 'bootstrap_started', 'agent_downloaded', 'runtime_downloaded', 'tunnel_downloaded',
    'runtime_installed', 'service_installed', 'registered', 'online', 'upgrading', 'upgraded', 'failed'
  )),
  error_code TEXT,
  message TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_key TEXT NOT NULL UNIQUE,
  severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
  kind TEXT NOT NULL,
  agent_id TEXT,
  node_id TEXT,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  occurrences INTEGER NOT NULL DEFAULT 1,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT,
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE reconcile_queue (
  agent_id TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  target_revision INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

CREATE INDEX idx_agents_last_seen ON agents(last_seen);
CREATE INDEX idx_revisions_agent ON revisions(agent_id, id DESC);
CREATE INDEX idx_nodes_enabled ON nodes(enabled);
CREATE INDEX idx_nodes_install_stage ON nodes(install_stage);
CREATE INDEX idx_nodes_ingress_ready ON nodes(ingress_mode, ingress_status, enabled);
CREATE INDEX idx_nodes_kind_ready ON nodes(node_kind, provisioned_at, enabled, retiring, draft);
CREATE INDEX idx_subscriptions_group ON subscriptions(group_id);
CREATE INDEX idx_subscription_group_nodes_node ON subscription_group_nodes(node_id);
CREATE INDEX idx_install_tickets_node ON install_tickets(node_id);
CREATE INDEX idx_install_tickets_expiry ON install_tickets(expires_at, used_at);
CREATE INDEX idx_install_events_node ON install_events(node_id, id DESC);
CREATE INDEX idx_alerts_status ON alerts(status, severity, last_seen_at DESC);
CREATE INDEX idx_reconcile_queue_updated ON reconcile_queue(updated_at);
