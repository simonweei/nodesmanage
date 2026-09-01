# NodeManage

部署在 Cloudflare Worker 上的精简 sing-box 节点管理平台。控制面、订阅和 D1 位于 Cloudflare；数据面可选择显式公网地址直连 VPS，或让 VLESS/Trojan WebSocket 经 Cloudflare Tunnel 进入只监听本机回环地址的 sing-box。

## 组件

- 一个 Cloudflare Worker（API + 静态管理界面）
- 一个 D1 数据库
- 一个静态 Go Agent
- VPS 上固定版本的 sing-box，以及 Tunnel 模式下固定版本的 cloudflared
- systemd/OpenRC（系统级）、systemd 用户服务（非 root），或无 init 容器的 standalone 进程模式

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
ADMIN_PASSWORD="至少六位的管理密码"
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

3. 设置管理密码 Secret。密码至少 6 个字符，值不会写入仓库：

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
2. 创建 VPS 时选择 Direct 或 Cloudflare Tunnel；部署策略默认使用“自动检测”，也可强制系统级或用户级，再复制一次性安装命令并在 15 分钟内执行。自动模式按命令的有效身份选择：root 使用系统级，普通用户使用用户级；低端口和 TLS/ACME 配置会要求系统级且不会静默提权。票据成功注册后立即失效，重新生成也会使旧票据失效。
   Bootstrap 只依赖基础 POSIX shell、`curl`/`wget`/BusyBox 之一以及任一常见 SHA-256 工具；它只下载并校验 Agent。
   Agent 根据系统环境安装固定版本的 sing-box 1.13.12；Tunnel 模式还会安装 cloudflared 2026.8.2。所有二进制均使用固定 SHA-256 摘要验证，并配置 systemd、OpenRC 或 standalone 进程管理。
3. 在订阅列表创建订阅，从当前全部 VPS 中勾选一个或多个节点。新建 VPS 会自动出现在选择列表中且默认不勾选，删除 VPS 会自动清理其订阅绑定。客户端随订阅自动生成并拥有独立凭据和订阅 Token；创建、编辑、停用或删除会自动发布所有受影响 VPS。
4. Agent 拉取修订后先执行 `sing-box check`，再通过 `/etc/nodemanage/releases` 下的 A/B 目录原子切换；重启失败时切回 `previous`。Tunnel 节点还必须通过公网 WebSocket Upgrade 探测，订阅只返回入口已验证、目标修订已应用、Agent 在线且 sing-box 正常运行的节点。

VPS 列表集中显示 Agent/sing-box/配置版本、CPU/内存/运行时间、在线状态、配置同步状态和常用操作。订阅 Token 和链接只在创建响应中显示一次。

系统级部署以 root 安装到 `/usr/local/bin`、`/etc/nodemanage` 和 `/etc/sing-box`，支持 systemd 与 OpenRC，也能监听 443 等低端口：

```bash
curl -fsSL https://管理域名/install.sh | sudo sh -s -- --ticket 一次性票据 --mode system
```

用户级部署必须由目标普通用户直接执行（不要使用 sudo），安装到 `~/.local/bin`、`$XDG_CONFIG_HOME/nodemanage` 和 `$XDG_STATE_HOME/nodemanage`，通过 `systemctl --user` 管理。它只允许 1025-65535 端口，Reality 默认使用 8443：

```bash
curl -fsSL https://管理域名/install.sh | sh -s -- --ticket 一次性票据 --mode user
```

自动部署命令使用 `--mode auto`。不带 `sudo` 时按普通用户安装，使用 `sudo` 或直接以 root 执行时按系统级安装。控制面会在 Agent 注册时重新校验最终模式与协议、端口是否兼容，并原子锁定实际部署模式；例如普通用户不能用自动模式绕过 443 低端口或 ACME 的系统级要求。

常规用户级部署使用 systemd 用户管理器。若 VPS 没有持续登录会话，管理员需执行 `loginctl enable-linger 用户名`；这一步属于系统策略，Agent 不会自行提权修改。无 systemd/OpenRC 时会自动回退 standalone，OpenRC 当前仅支持系统级部署。

当 PID 1 不是 systemd 且没有 OpenRC（例如 Cloud Studio、部分 Docker/LXC 容器）时，Agent 0.11.0 会自动使用 `standalone` 模式，通过独立进程、PID 文件和日志管理 sing-box、Agent 和 cloudflared。该模式可完成配置同步、健康检查、重启和回滚，但无法保证容器或工作区重建后的开机自启；生产 VPS 仍优先使用 systemd/OpenRC。

Tunnel 模式只提供 Cloudflare Public Hostname 能直接承载的 VLESS/Trojan + TLS + WebSocket 组合：sing-box 只监听 `127.0.0.1:高位端口`，TLS 在 Cloudflare 边缘终止。Quick Tunnel 固定公网端口 443 且只能启用一个协议，会自动发现随机 `trycloudflare.com` 域名，适合实机诊断，不提供 SLA；生产应选择 Named Tunnel，可同时启用两个协议，每个协议分别使用 443、2053、2083、2087、2096 或 8443 中不重复的公网端口、本地端口和 WebSocket 路径。Agent 在 `127.0.0.1` 提供轻量路径路由，再转发到各 sing-box 入站。创建 Named Tunnel VPS 时需填写已配置路由的域名和 Tunnel Token；Token 只在当前浏览器页面中用于生成一次性安装命令，不会上传或写入 D1，安装后仅保存在 VPS 的 `0600` Agent 配置中。

Named Tunnel 的“公网域名”必须填写 Cloudflare Zero Trust 中该 Tunnel 已配置的 Public Hostname，例如 `tunnel.serverdomain.com`，不能填写源站 IP，也不会像 Quick Tunnel 一样自动生成。Direct 模式只需填写一次公网连接地址和一次公共 ACME 邮箱：选择 TLS 协议时，控制面自动将公网域名用于订阅地址、TLS/SNI、证书域名及 WebSocket Host。若 VPS 公网域名是 `serverdomain.com`，请先让其 A/AAAA 记录直连 VPS，再填写 `serverdomain.com` 和有效邮箱；每个协议仅需分别设置监听端口、WebSocket 路径或 gRPC Service Name。

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
| Trojan TLS + WebSocket | TCP | system/root | ACME 域名；Tunnel 模式由 Cloudflare 边缘终止 TLS |

Shadowsocks 固定使用 `2022-blake3-aes-128-gcm` 多用户模式。Direct TLS 证书由 Agent 0.11.0 的统一证书管理器通过 Let's Encrypt HTTP-01 申请和续期，因此域名必须先解析到 VPS，TCP 80 必须可从公网访问。多个 TLS 协议可以同时启用：相同域名和 ACME 邮箱只签发一张证书并共享文件，不同域名分别管理；证书通过版本目录和 `current` 原子软链切换，续期失败会继续使用仍有效的旧证书并指数退避重试。用户级部署仍只允许 Reality 和 Shadowsocks，因为 HTTP-01 需要系统级监听和稳定的 `/etc/nodemanage/certificates` 状态目录。Cloudflare Tunnel 由边缘终止 TLS，不在 VPS 申请证书。

“订阅连接域名”允许与 Agent 上报地址分离：WebSocket/gRPC 可填写 Cloudflare 代理域名，Reality、Trojan、Hysteria2 和 TUIC 通常填写直连域名。Direct 的 TCP 协议默认分别使用 Cloudflare 常见 HTTPS 端口：VLESS Reality 8443、Shadowsocks 2053、VLESS WebSocket 443、VLESS gRPC 2083、Trojan TLS 2087、Trojan WebSocket 2096；Hysteria2 和 TUIC 默认分别使用 UDP 9443 和 10443。所有协议默认端口互不重复，用户仍可手动修改；同一传输层的协议不能占用同一端口。

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
- `nodemanage-agent diagnose --full`：增加版本、权限、配置校验和当前配置版本，输出自动避开 Token。
- `nodemanage-agent status`：输出 Agent、sing-box、Tunnel、入口和当前配置状态。
- `nodemanage-agent logs --component agent --tail 200`：按组件读取最近日志，不上传到管理端。
- `nodemanage-agent help [command]`：显示全部命令或单个命令的参数说明。
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
