# NodeManage 生产运行手册

## 发布前门禁

1. 执行 `npm ci`、`npm run check`、`cd agent && go test ./...`。
2. Agent 有改动时执行 `powershell -File scripts/build-agent.ps1`（Linux/macOS 使用 `scripts/build-agent.sh`），并提交二进制、`SHA256SUMS`、稳定清单和生成的 TypeScript 摘要。
3. 执行 `npm run db:remote`；只允许 Wrangler 写入 `d1_migrations`，不要在控制台手工插入迁移记录。
4. 确认 `ADMIN_PASSWORD` 至少 12 个字符，`AGENT_TOKEN_SECRET` 是独立的至少 32 字符随机 Secret。
5. 执行 `npm run deploy`，随后请求 `/healthz`，必须返回 HTTP 200 且 database/secrets 均为 ready。

数据库迁移必须先于包含新 SQL 的 Worker 发布。当前数据库是全新架构，只有 `0001_current_schema.sql`；后续已经进入生产后，只能新增迁移，禁止修改已经应用的迁移文件。

## 备份与恢复

发布数据库迁移前及每日保留一份远程导出：

```powershell
powershell -File scripts/backup-d1.ps1
```

Linux/macOS：

```sh
./scripts/backup-d1.sh
```

导出文件位于 `backups/`，被 Git 忽略。应由外部备份任务复制到访问受控、版本化的存储，并定期演练导入到临时 D1，而不是只确认文件存在。

误操作后优先使用 D1 Time Travel：

```bash
npx wrangler d1 time-travel info nodemanage --timestamp "2026-08-28T12:00:00Z"
npx wrangler d1 time-travel restore nodemanage --timestamp "2026-08-28T12:00:00Z"
```

恢复会修改远程生产库。执行前先导出当前状态、记录目标 UTC 时间并暂停管理写入，恢复后检查 `/healthz`、表结构、VPS 数量和订阅数量。

## 监控与告警

- Worker Observability、日志和 5% trace 已在 Wrangler 配置中开启。
- Cron 每 5 分钟重试未完成的配置发布，清理过期数据，并在 `alerts` 中创建或解除 Agent 离线和配置应用失败告警；面板顶部显示未解除告警。
- 在 Cloudflare 控制台为 Worker 错误率、CPU/请求异常和 D1 错误建立外部通知。数据库内告警只在管理员打开面板时可见，不能代替站外通知。
- 正常 Agent 上报间隔为 60 秒。离线超过 5 分钟、`last_error` 非空、`current_revision != desired_revision` 持续不收敛都需要处理。

常用只读检查：

```bash
npx wrangler d1 execute nodemanage --remote --command "SELECT status,severity,kind,message,last_seen_at FROM alerts WHERE status='open' ORDER BY last_seen_at DESC;"
npx wrangler d1 execute nodemanage --remote --command "SELECT n.name,a.last_seen,a.current_revision,a.desired_revision,a.last_error FROM nodes n LEFT JOIN agents a ON a.id=n.agent_id ORDER BY n.name;"
```

## 故障处理

- Agent 离线：在 VPS 执行 `nodemanage-agent diagnose`，检查服务、DNS、系统时间和到 Worker HTTPS 的出站访问；随后执行 `nodemanage-agent repair`。
- 配置失败：面板查看错误及安装事件。Agent 会在 `sing-box check` 或重启失败时回滚到 previous；修正 Profile 后保存会自动生成新修订。
- 配置发布中断：变更与 `reconcile_queue` 在同一个 D1 事务写入，Cron 会重试；也可在面板点击“发布”立即重试。
- TLS/ACME 失败：确认域名 A/AAAA 记录确实指向当前 VPS、TCP 80 入站可达、系统时间正确，并检查 `/etc/nodemanage/acme` 可写。Hysteria2/TUIC 使用 UDP，Cloudflare 普通代理不能转发该流量，记录必须为 DNS only。WebSocket/gRPC 走 Cloudflare 时还需确认端口在代理支持范围内，gRPC 已在域名网络设置中启用。
- 订阅泄露：在订阅管理中轮换 Token；旧 Token 立即失效。删除客户端/订阅也会立即撤销 Token 并自动发布 VPS 用户列表。
- VPS 下线：先“安全退役”，等待空用户配置应用后再次删除；只有机器已经不可访问且明确接受残留配置风险时才强制删除。
- Worker 回滚：回滚 Worker 代码不能自动回滚数据库。新迁移若不向后兼容，应使用 Time Travel 或经过验证的前向修复迁移。

## 容量和安全边界

- 单控制面最多 200 台 VPS、200 个订阅组；单次订阅最多 8 台 VPS、10 个初始客户端。
- 生产协议支持 VLESS Reality + Vision、Shadowsocks AEAD 2022、VLESS TLS + WebSocket、VLESS TLS + gRPC、Hysteria2、TUIC 和 Trojan TLS。TLS/ACME 协议仅允许 system/root，且每台 VPS 最多一个；上线前必须验证 TCP 80、目标 TCP/UDP 端口、DNS 和证书续期。
- 控制面不执行远程 Shell，不下发任意命令。Agent 只接受声明式 sing-box 配置和固定、带 SHA-256 的发布清单。
- 管理登录和公共 Agent/订阅接口分别使用 Cloudflare Rate Limiting binding。真正的管理域名还应启用 Cloudflare Access 或等价的身份边界。
