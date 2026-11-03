# oh-my-acme

单用户自用的 ACME 证书集中管理工具 —— 轻量、接近 `acme.sh` 的使用方式。

- **Server**：通过 Web UI 统一申请、续期通配符证书，并下发给多台 Agent。
- **Agent**：安装到目标服务器，接收证书、原子替换、校验 Nginx 配置并 `reload`。

## 特性

- Go 原生 ACME，支持通配符证书（`example.com` + `*.example.com`）
- DNS-01 验证，Cloudflare（`CF_Token` / `CF_Zone_ID` / `CF_Account_ID`）
- 自动 / 手动续期，Agent 下发失败可在 Web UI 手动重试
- 手动下发前可选择本次同步的目标 Agent，支持全选 / 取消全选；自动续期仍下发到全部配置目标
- Web / Telegram 手动签发、下发前需确认域名与操作，下发确认中列明本次目标 Agent
- 内部自签 CA 的 mTLS 通信，不依赖任何第三方 CA
- Server 与 Agent 通过 GitHub Release 的 `install.sh` 安装为 systemd 服务
- Web UI：Go 模板 + HTMX + 已编译 CSS，单二进制，简体中文，完全离线
- 按钮与导航使用 [Heroicons](https://heroicons.com/) 线框 SVG，图标与许可随程序内嵌

## 快速开始（开发）

```bash
go test ./...
go run ./cmd/server -config ./server/config.example.json
```

生产安装脚本随每个 GitHub Release 发布为 `install-server.sh` 和
`install-agent.sh`；源码位于 `server/install.sh` 与 `agent/install.sh`。

## Web 更新

支持更新功能的版本可以在 Web UI 中手动检测正式 Release：Server 在“设置”中选择更高版本自更新；Agent 在 Agent 列表中一键更新，Server 只发送目标版本号，Agent 自行从固定 GitHub 仓库下载并校验 SHA-256，不接受远程命令、URL 或路径。

`v0.1.0` 本身没有更新接口，因此从 `v0.1.0` 迁移到第一个支持 Web 更新的版本时，Server 和现有 Agent 都需要最后手动运行一次新版安装脚本。现有 Agent 已有 `config.json` 时只需传 `-version`，不需要重新注册；之后的版本才能通过 Web UI 升级。

## Agent 来源限制

Agent 首次注册成功后会把实际连接到的 Server IP 记录为精确的
`allowed_server_cidrs`（IPv4 `/32`、IPv6 `/128`），并在 TLS 握手前拒绝其他来源。
旧版配置升级后会从 `server_url` 解析并持久化当前地址。Server 有多个出口地址时，
可在 Agent 的 `config.json` 中配置多个 IP 或 CIDR；Server IP 变更时需要先更新该列表并重启 Agent。

## Web UI 样式

部署运行、普通 `go build` 和 GitHub Release 都使用仓库中已提交的 `internal/server/web/static/app.css`，不需要 Node、npm、CDN 或在线字体。只有修改 Tailwind 源文件 `internal/server/web/styles/app.css` 时才需要 Node 22 开发工具：

```bash
npm ci
npm run test-web    # 前端交互回归测试
make web-css        # 编译并覆盖已提交的 CSS
make web-css-check  # 确认已提交 CSS 与源文件一致，不修改工作区
```

`make build` 不会调用 npm。CI 中的 Web UI workflow 只检查 CSS 产物是否过期，release 工作流仍是纯 Go 构建。
两个 workflow 都只在发布 GitHub Release（含预发布）时触发，使用该 Release 的标签版本；普通提交、PR、仅推送标签及保存 Release 草稿均不会触发。构建完成后，安装包、安装脚本和校验文件会上传到已发布的 Release。

## 管理员登录记录

Web「设置」展示最近 50 次登录尝试（成功与失败合计），按最新优先排列，超过 50 条自动淘汰最早记录，重启后保留。记录包含用户名、UTC 登录时间、来源 IP、结果、设备 / 系统、浏览器版本、User-Agent 和 SHA-256 浏览器环境指纹；密码和会话令牌不写入记录。指纹由请求头与浏览器的语言、时区、屏幕、平台等环境信息生成，仅供辅助识别，可能变化或被伪造；禁用 JavaScript 时退回请求头指纹。

反向代理部署时，在 Server 的 `config.json` 中设置 `trusted_proxies`（代理 IP 或 CIDR）。仅可信代理的 `X-Forwarded-For` / `X-Real-IP` 会用于来源识别；未配置时记录直连 IP。代理应覆盖客户端提交的转发头，或正确追加实际来源地址。

## Google Authenticator 两步验证

默认关闭。在 Web「设置 → 两步验证」中输入当前密码，使用 Google Authenticator 扫描二维码（或手动输入设置密钥，选择基于时间），再输入 6 位验证码确认启用。二维码在服务端本地生成；待确认绑定仅保留在当前会话中，10 分钟过期，重启后需重新开始。

启用后，Web 登录需同时提供密码和验证码。采用 SHA-1、6 位、30 秒周期的标准 TOTP，允许前后一个周期的时间误差；已使用的验证码不可重复使用，请保持服务器和手机时间同步。认证及两步验证设置操作合计每分钟最多尝试 10 次。

启用时显示 10 个一次性恢复码，请立即妥善保存；服务端只保存恢复码哈希，之后无法再次查看。丢失手机时可用密码和一个未使用的恢复码登录。关闭两步验证也需要当前密码及有效验证码或恢复码；需要换绑或更新恢复码时，可关闭后重新绑定。启用和关闭均会撤销其他 Web 会话。

TOTP 绑定密钥使用 AES-256-GCM 加密后保存在权限为 `0600` 的 `state.json` 中，每次加密使用新的随机 nonce，并校验认证标签。恢复码继续只保存哈希，防重放状态随账户持久保存。两步验证仅用于管理员 Web 登录。

### 配置绑定密钥加密

服务进程通过环境变量 `TWO_FACTOR_ENCRYPTION_KEY` 读取加密密钥，格式为 **32 字节随机数据的标准 Base64 编码**。它不会自动生成、写入 `config.json`、账户状态或日志。可使用 `openssl rand -base64 32` 生成一次，并将结果妥善保存。

安装脚本生成的 systemd 服务会读取 `/opt/oh-my-acme-server/server.env`（自定义安装目录时使用对应目录）。创建权限为 `0600` 的文件，填写：

```dotenv
TWO_FACTOR_ENCRYPTION_KEY=这里填写生成的Base64密钥
```

已有 systemd 服务可执行 `sudo systemctl edit oh-my-acme-server`，加入：

```ini
[Service]
EnvironmentFile=/opt/oh-my-acme-server/server.env
```

保存后执行 `sudo systemctl daemon-reload` 和 `sudo systemctl restart oh-my-acme-server`。直接运行程序时，将该变量设置到启动程序的环境中即可；只在交互终端中 `export` 不会传给 systemd 服务。

未绑定 2FA 时可以不配置此变量，但无法开始绑定。存在绑定密钥（包括本地备份）时，缺失、格式错误或无法解密的密钥会阻止启动；运行中解密失败也不会绕过验证。请备份并在重启、更新后保留同一个密钥，直接替换或丢失会导致已有绑定数据无法解密。

升级时，在启动监听和常规状态写入前，自动迁移 `state.json` 与 `state.json.backup` 内的旧版明文绑定密钥，保留原绑定、恢复码和防重放状态；迁移失败则停止启动。其他位置的历史备份不在迁移范围内。
