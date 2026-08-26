PRAGMA foreign_keys = OFF;

CREATE TABLE profiles_v2 (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN (
    'vless-reality-vision', 'vless-tls-ws', 'vless-tls-grpc', 'trojan-tls',
    'hysteria2-tls', 'hysteria2-tls-obfs', 'tuic-tls', 'shadowsocks-aead'
  )),
  settings_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO profiles_v2(id,name,type,settings_json,created_at,updated_at)
SELECT id,name,'vless-reality-vision',
  json_set(
    json_remove(settings_json, '$.vless_port', '$.reality_server_name'),
    '$.listen_port', json_extract(settings_json, '$.vless_port'),
    '$.server_name', json_extract(settings_json, '$.reality_server_name')
  ),created_at,updated_at FROM profiles;
DROP TABLE profiles;
ALTER TABLE profiles_v2 RENAME TO profiles;

ALTER TABLE clients ADD COLUMN trojan_password TEXT;
ALTER TABLE clients ADD COLUMN tuic_password TEXT;
ALTER TABLE clients ADD COLUMN shadowsocks_password TEXT;
UPDATE clients SET
  trojan_password=lower(hex(randomblob(24))),
  tuic_password=lower(hex(randomblob(24))),
  shadowsocks_password=lower(hex(randomblob(16)));

PRAGMA foreign_keys = ON;
