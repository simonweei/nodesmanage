# NodeManage

部署在 Cloudflare Worker 上的精简 sing-box 节点管理平台。Cloudflare 仅承载管理控制面和客户端订阅，代理 TCP/UDP 流量始终由客户端直连 VPS。

## 组件

- 一个 Cloudflare Worker（API + 静态管理界面）
- 一个 D1 数据库
- 一个静态 Go Agent
- VPS 上的 sing-box + systemd/OpenRC

没有 KV、R2、Queue、Durable Objects、WebSocket、远程 Shell 或动态脚本执行。Cron 仅清理过期安装票据和 90 天前的安装事件。

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

1. 在 VPS 列表点击“创建 VPS”，选择协议组合并确认少量必要参数。Reality 密钥、Short ID、Hysteria2 混淆密码和 Shadowsocks 主密码均由 Worker 自动生成。
2. 复制该 VPS 的一次性安装命令并在 15 分钟内执行。票据成功注册后立即失效，重新生成也会使旧票据失效。
   Bootstrap 只依赖基础 POSIX shell、`curl`/`wget`/BusyBox 之一以及任一常见 SHA-256 工具；它只下载并校验 Agent。
   Agent 根据系统环境安装固定版本的 sing-box 1.13.12，所有二进制均使用固定 SHA-256 摘要验证，并配置 systemd 或 OpenRC 服务。
3. 在订阅列表创建订阅，选择一个或多个 VPS，再添加一个或多个客户端。每个客户端拥有独立凭据和订阅 Token。
4. 回到 VPS 列表发布配置。Agent 会先执行 `sing-box check`，再通过 `/etc/nodemanage/releases` 下的 A/B 目录原子切换；重启失败时切回 `previous`。

VPS 列表集中显示 Agent/sing-box/配置版本、CPU/内存/运行时间、在线状态、配置同步状态和常用操作。订阅 Token 和链接只在创建响应中显示一次。

第一版固定支持：VLESS Reality + Vision、VLESS TLS + WS、VLESS TLS + gRPC、Trojan TLS、Hysteria2 TLS、Hysteria2 TLS + Salamander、TUIC TLS、Shadowsocks AEAD 2022。AnyTLS、VMess、ShadowTLS 和 Naive 暂不进入生成器。

所有普通 TLS Profile 都不负责证书申请。使用前需要在 VPS 上准备证书和私钥，并在 Profile 中填写路径。Shadowsocks 固定使用 `2022-blake3-aes-128-gcm` 多用户模式；TUIC 固定关闭 0-RTT。

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
- `nodemanage-agent uninstall`：保留配置卸载；`--purge` 同时删除配置。

sing-box 首选从 Worker Assets 的版本化镜像下载，失败后回退官方 GitHub Release；所有来源必须匹配同一个 SHA-256。构建脚本自动生成 `src/generated-releases.ts` 和 `public/downloads/stable.json`，`npm run release:check` 会阻止摘要漂移。安装阶段和错误码同时写入 VPS 的 `/var/log/nodemanage-install.log` 与 D1，面板“更多”中可查看最近事件。

## 验证

```bash
npm run check
cd agent && go test ./...
```

Debian、Ubuntu、Rocky 和 Alpine 的 amd64/arm64 容器兼容性矩阵定义在 `.github/workflows/platform-matrix.yml`。
