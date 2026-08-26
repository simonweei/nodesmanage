# NodeManage

部署在 Cloudflare Worker 上的精简 sing-box 节点管理平台。Cloudflare 仅承载管理控制面和客户端订阅，代理 TCP/UDP 流量始终由客户端直连 VPS。

## 组件

- 一个 Cloudflare Worker（API + 静态管理界面）
- 一个 D1 数据库
- 一个静态 Go Agent
- VPS 上的 sing-box + systemd

没有 KV、R2、Queue、Durable Objects、Cron、WebSocket、远程 Shell或自动升级。

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
   ```

   使用 Cloudflare Git 构建时，也可以在 Worker 的 **Settings → Variables and Secrets** 中添加同名加密 Secret。

4. 应用数据库迁移并部署：

   ```bash
   npm run db:remote
   npm run deploy
   ```

访问管理域名时会跳转到密码登录页。登录会话有效 12 小时，并使用签名的 `HttpOnly`、`SameSite=Strict` Cookie；修改 `ADMIN_PASSWORD` 会立即令已有会话失效。Agent、订阅和安装码继续使用各自独立 Token，不依赖控制面板会话。

## 使用流程

1. 在管理界面创建永久安装码。`最大使用次数` 留空时可以长期重复使用；禁用安装码即可停止后续注册。
2. 在 VPS 执行界面生成的一行命令。脚本固定安装 sing-box 1.13.12，并校验官方 checksums 文件。
3. 创建客户端。
4. 从 8 个固定协议组合创建 Profile。Reality 密钥、Short ID、Hysteria2 混淆密码和 Shadowsocks 主密码均由 Worker 自动生成。
5. 把 Agent、Profile 和节点连接地址绑定。
6. 发布配置。Agent 会先执行 `sing-box check`，失败时不替换当前配置；重启失败时恢复单个备份配置。
7. 创建订阅，Token 和链接只在创建响应中显示一次。

第一版固定支持：VLESS Reality + Vision、VLESS TLS + WS、VLESS TLS + gRPC、Trojan TLS、Hysteria2 TLS、Hysteria2 TLS + Salamander、TUIC TLS、Shadowsocks AEAD 2022。AnyTLS、VMess、ShadowTLS 和 Naive 暂不进入生成器。

所有普通 TLS Profile 都不负责证书申请。使用前需要在 VPS 上准备证书和私钥，并在 Profile 中填写路径。Shadowsocks 固定使用 `2022-blake3-aes-128-gcm` 多用户模式；TUIC 固定关闭 0-RTT。

## Agent 上报的权限

- 运行用户名、UID/EUID/GID
- 是否 root
- `/proc/self/status` 中的有效 Linux capabilities
- sing-box 配置可读、可写状态
- sing-box 是否可以执行
- 是否具备 systemd 服务控制条件

Agent 不提权、不执行管理端传来的命令，也不会为了检测权限而修改文件。

## 验证

```bash
npm run check
cd agent && go test ./...
```
