PRAGMA foreign_keys = OFF;

ALTER TABLE agents ADD COLUMN cpu_usage_percent REAL;

CREATE TABLE nodes_v3 (
  id TEXT PRIMARY KEY,
  agent_id TEXT UNIQUE,
  profile_id TEXT NOT NULL,
  name TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  draft INTEGER NOT NULL DEFAULT 0 CHECK (draft IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
  FOREIGN KEY (profile_id) REFERENCES profiles(id)
);

INSERT INTO nodes_v3(id,agent_id,profile_id,name,address,enabled,created_at,updated_at)
SELECT id,agent_id,profile_id,name,address,enabled,created_at,updated_at FROM nodes;
DROP TABLE nodes;
ALTER TABLE nodes_v3 RENAME TO nodes;

ALTER TABLE enrollment_codes ADD COLUMN node_id TEXT;

CREATE TABLE subscription_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE subscriptions ADD COLUMN group_id TEXT;
INSERT INTO subscription_groups(id,name,enabled,created_at,updated_at)
SELECT id,name,enabled,created_at,created_at FROM subscriptions;
UPDATE subscriptions SET group_id=id;

CREATE TABLE subscription_group_nodes (
  group_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  PRIMARY KEY (group_id,node_id),
  FOREIGN KEY (group_id) REFERENCES subscription_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

INSERT INTO subscription_group_nodes(group_id,node_id)
SELECT g.id,n.id FROM subscription_groups g CROSS JOIN nodes n WHERE n.enabled=1;

CREATE INDEX idx_nodes_enabled ON nodes(enabled);
CREATE INDEX idx_enrollment_codes_node ON enrollment_codes(node_id);
CREATE INDEX idx_subscriptions_group ON subscriptions(group_id);
CREATE INDEX idx_subscription_group_nodes_node ON subscription_group_nodes(node_id);

PRAGMA foreign_keys = ON;
