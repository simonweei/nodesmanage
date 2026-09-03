ALTER TABLE nodes ADD COLUMN node_kind TEXT NOT NULL DEFAULT 'managed' CHECK (node_kind IN ('managed', 'minimal'));
ALTER TABLE nodes ADD COLUMN provisioned_at TEXT;

CREATE INDEX idx_nodes_kind_ready ON nodes(node_kind, provisioned_at, enabled, retiring, draft);
