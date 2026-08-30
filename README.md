# NodeManage

部署在 Cloudflare Worker 上的精简 sing-box 节点管理平台。Cloudflare 仅承载管理控制面和客户端订阅，代理 TCP/UDP 流量始终由客户端直连 VPS。

## 组件

- 一个 Cloudflare Worker（API + 静态管理界面）
- 一个 D1 数据库
- 一个静态 Go Agent
- VPS 上的 sing-box + systemd/OpenRC（系统级）或 systemd 用户服务（非 root）

没有 KV、R2、Queue、Durable Objects、WebSocket、远程 Shell 或动态脚本执行。D1 中的 `reconcile_queue` 与业务变更同事务写入，Cron 每 5 分钟重试配置发布、维护告警并清理过期数据。

## 本地开发

要求 Node.js 22+、Go 1.22+。

```bash
npm install
npm run types
npm run db:local
npm run dev
```

本地开发前创建不会提交到 Git 的 `.dev.vars`：

```dotenv
ADMIN_PASSWORD="至少十二位的管理密码"
AGENT_TOKEN_SECRET="至少三十二位的独立随机值"
```

## 部署

1. 创建 D1，并把返回的数据库 ID 写入 `wrangler.jsonc`：

   ```bash
   npx wrangler d1 create nodemanage
   ```

2. 构建两种 Linux Agent：

   ```bash
   ./scripts/build-agent.sh
   ```

3. 设置管理密码 Secret。密码至少 12 个字符，值不会写入仓库：

   ```bash
   npx wrangler secret put ADMIN_PASSWORD
   npx wrangler secret put AGENT_TOKEN_SECRET
   ```

   `AGENT_TOKEN_SECRET` 应使用独立的 32 字节以上随机值，用于安装注册幂等凭据派生。使用 Cloudflare Git 构建时，也可以在 Worker 的 **Settings → Variables and Secrets** 中添加同名加密 Secret。

4. 应用数据库迁移并部署：

   ```bash
   npm run db:remote
   npm run deploy
   ```

访问管理域名时会跳转到密码登录页。登录会话有效 12 小时，并使用签名的 `HttpOnly`、`SameSite=Strict` Cookie；修改 `ADMIN_PASSWORD` 会立即令已有会话失效。Agent、订阅和一次性安装票据使用各自独立 Token，不依赖控制面板会话。

## 使用流程

管理界面只有 **VPS** 和 **订阅** 两个主版块，桌面端使用紧凑表格，移动端自动切换为卡片和全屏编辑抽屉。

1. 在 VPS 列表点击“创建 VPS”，选择协议组合并确认少量必要参数。Reality 密钥、Short ID、Shadowsocks 主密码和 Hysteria2 混淆密码均由 Worker 自动生成。
2. 创建 VPS 时选择系统级或用户级部署，再复制一次性安装命令并在 15 分钟内执行。票据成功注册后立即失效，重新生成也会使旧票据失效。
   Bootstrap 只依赖基础 POSIX shell、`curl`/`wget`/BusyBox 之一以及任一常见 SHA-256 工具；它只下载并校验 Agent。
   Agent 根据系统环境安装固定版本的 sing-box 1.13.12，所有二进制均使用固定 SHA-256 摘要验证，并配置 systemd 或 OpenRC 服务。
3. 在订阅列表创建订阅，选择一个或多个已安装 VPS，再添加一个或多个客户端。每个客户端拥有独立凭据和订阅 Token；创建、编辑、停用或删除会自动发布所有受影响 VPS。
4. Agent 拉取修订后先执行 `sing-box check`，再通过 `/etc/nodemanage/releases` 下的 A/B 目录原子切换；重启失败时切回 `previous`。订阅只返回已经应用目标修订、Agent 在线且 sing-box 正常运行的节点。

VPS 列表集中显示 Agent/sing-box/配置版本、CPU/内存/运行时间、在线状态、配置同步状态和常用操作。订阅 Token 和链接只在创建响应中显示一次。

系统级部署以 root 安装到 `/usr/local/bin`、`/etc/nodemanage` 和 `/etc/sing-box`，支持 systemd 与 OpenRC，也能监听 443 等低端口：

```bash
curl -fsSL https://管理域名/install.sh | sudo sh -s -- --ticket 一次性票据 --mode system
```

用户级部署必须由目标普通用户直接执行（不要使用 sudo），安装到 `~/.local/bin`、`$XDG_CONFIG_HOME/nodemanage` 和 `$XDG_STATE_HOME/nodemanage`，通过 `systemctl --user` 管理。它只允许 1025-65535 端口，Reality 默认使用 8443：

```bash
curl -fsSL https://管理域名/install.sh | sh -s -- --ticket 一次性票据 --mode user
```

用户级部署要求 systemd 用户管理器可用。若 VPS 没有持续登录会话，管理员需执行 `loginctl enable-linger 用户名`；这一步属于系统策略，Agent 不会自行提权修改。OpenRC 当前仅支持系统级部署。

生产协议包括：

| 协议 | 传输 | 部署模式 | 域名要求 |
| --- | --- | --- | --- |
| VLESS Reality + Vision | TCP | system / user | 不需要证书域名 |
| Shadowsocks AEAD 2022 | TCP + UDP | system / user | 不需要域名 |
| VLESS TLS + WebSocket | TCP | system/root | ACME 域名；可使用 Cloudflare 代理 |
| VLESS TLS + gRPC | TCP | system/root | ACME 域名；使用 Cloudflare 时需启用 gRPC |
| Hysteria2 | UDP/QUIC | system/root | ACME 域名，必须 DNS only 直连 VPS |
| TUIC | UDP/QUIC | system/root | ACME 域名，必须 DNS only 直连 VPS |
| Trojan TLS | TCP | system/root | ACME 域名，建议 DNS only 直连 VPS |

Shadowsocks 固定使用 `2022-blake3-aes-128-gcm` 多用户模式。TLS 协议由 sing-box 1.13.12 通过 Let's Encrypt HTTP-01 自动申请和续期证书，因此域名必须先解析到 VPS，TCP 80 必须可从公网访问。为避免多个 ACME 挑战监听器竞争端口，每台 VPS 最多启用一个 TLS/ACME 协议。用户级部署仍只允许 Reality 和 Shadowsocks；这不是端口号限制，而是 ACME 需要系统级监听和稳定的 `/etc/nodemanage/acme` 状态目录。

“订阅连接域名”允许与 Agent 上报地址分离：WebSocket/gRPC 可填写 Cloudflare 代理域名，Reality、Trojan、Hysteria2 和 TUIC 通常填写直连域名。TCP 与 UDP 协议可以复用相同端口，同一传输层的协议不能占用同一端口。

## Agent 上报的权限

- 运行用户名、UID/EUID/GID
- 是否 root
- `/proc/self/status` 中的有效 Linux capabilities
- sing-box 配置可读、可写状态
- sing-box 是否可以执行
- 发行版、libc、init system、安装模式及低端口绑定能力
- 是否具备 systemd/OpenRC 服务控制条件

Agent 不提权、不执行管理端传来的命令，也不会为了检测权限而修改文件。

VPS 上可使用：

- `nodemanage-agent diagnose`：输出平台和服务诊断。
- `nodemanage-agent repair`：按固定 Manifest 重新下载损坏或缺失的二进制，修复配置、权限和服务。
- `nodemanage-agent upgrade`：升级 Agent/sing-box，版本或服务健康检查失败时恢复旧二进制。
- `nodemanage-agent uninstall`：自动按当前执行用户卸载对应模式；`--purge` 同时删除配置。也可显式指定 `--mode system|user`。

sing-box 首选从 Worker Assets 的版本化镜像下载，失败后回退官方 GitHub Release；所有来源必须匹配同一个 SHA-256。构建脚本自动生成 `src/generated-releases.ts` 和 `public/downloads/stable.json`，`npm run release:check` 会阻止摘要漂移。安装阶段和错误码同时写入 VPS 的 `/var/log/nodemanage-install.log` 与 D1，面板“更多”中可查看最近事件。

## 验证

```bash
npm run check
cd agent && go test ./...
```

Debian、Ubuntu、Rocky 和 Alpine 的 amd64/arm64 容器兼容性矩阵定义在 `.github/workflows/platform-matrix.yml`。

生产发布、D1 导出/Time Travel、告警和故障处理步骤见 [生产运行手册](docs/production-runbook.md)。控制面限制为最多 200 台 VPS、200 个订阅组；单个订阅最多绑定 8 台 VPS。
