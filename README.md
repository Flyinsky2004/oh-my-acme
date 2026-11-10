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

启用后，Web 登录需同时提供密码和验证码。采用 SHA-1、6 位、30 秒周期的标准 TOTP，允许前后一个周期的时间误差；已使用的验证码不可重复使用，请保持服务器和手机时间同步。认证请求按来源限流；只有密码通过后的认证与两步验证操作才使用账户级额度，匿名错误请求不会消耗其他来源的账户级额度。来源计数器有固定容量和过期清理。

启用时显示 10 个一次性恢复码，请立即妥善保存；服务端只保存恢复码哈希，之后无法再次查看。丢失手机时可用密码和一个未使用的恢复码登录。关闭两步验证也需要当前密码及有效验证码或恢复码；需要换绑或更新恢复码时，可关闭后重新绑定。启用和关闭均会撤销其他 Web 会话。

TOTP 绑定密钥使用 AES-256-GCM 加密后保存在权限为 `0600` 的 `state.json` 中，每次加密使用新的随机 nonce，并校验认证标签。恢复码继续只保存哈希，防重放状态随账户持久保存。两步验证仅用于管理员 Web 登录。

### 配置绑定密钥加密

在现有 `/opt/oh-my-acme-server/config.json` 中添加 `two_factor_encryption_key`，格式为 **32 字节随机数据的标准 Base64 编码**。可使用 `openssl rand -base64 32` 生成一次，将结果填入现有配置文件的这个字段（保留其他字段）：

```json
{
  "two_factor_encryption_key": "这里填写生成的Base64密钥"
}
```

配置文件权限应为 `0600`。部署新版程序并修改配置后，执行 `sudo systemctl restart oh-my-acme-server` 即可。自定义安装目录时使用对应配置文件。密钥不会自动生成，也不会写入账户状态或日志。

同时兼容环境变量 `TWO_FACTOR_ENCRYPTION_KEY`：**非空环境变量优先于配置文件**，空值或未设置时使用配置文件。此前通过环境文件配置过密钥的部署可以继续使用；迁移到 `config.json` 时应复制同一个密钥，并移除旧环境变量以避免覆盖。

安装脚本生成的 systemd 服务也会读取可选的 `/opt/oh-my-acme-server/server.env`。需要使用环境变量的已有服务可通过 `sudo systemctl edit oh-my-acme-server` 添加 `[Service]` 下的 `EnvironmentFile=/opt/oh-my-acme-server/server.env`，环境文件内填写 `TWO_FACTOR_ENCRYPTION_KEY=生成的Base64密钥` 并设置权限 `0600`，然后执行 `sudo systemctl daemon-reload` 和 `sudo systemctl restart oh-my-acme-server`。只在交互终端中 `export` 不会传给 systemd 服务。

未绑定 2FA 时可以不配置加密密钥，但无法开始绑定。存在绑定密钥（包括本地备份）时，缺失、格式错误或无法解密的密钥会阻止启动；运行中解密失败也不会绕过验证。请备份并在重启、更新后保留同一个密钥，直接替换或丢失会导致已有绑定数据无法解密。

升级时，在启动监听和常规状态写入前，自动迁移 `state.json` 与 `state.json.backup` 内的旧版明文绑定密钥，保留原绑定、恢复码和防重放状态；迁移失败则停止启动。其他位置的历史备份不在迁移范围内。

## 安全修复与升级兼容

### Web 会话、来源与反向代理

所有管理员写操作均要求当前会话的 CSRF Token，包括普通表单、HTMX、退出登录、证书签发和部署、Agent 管理、设置和更新。页面会自动携带 Token；自动化客户端需先登录取得当前页面中的 Token，再通过表单正文的 `csrf` 或 `X-CSRF-Token` 请求头提交。URL 中的 Token 不被接受。退出、过期及会话轮换后，旧 Token 失效。

写请求同时检查 `Origin`，或在缺失时检查 `Referer`，要求协议、主机和端口同源；同站兄弟子域名也被拒绝。没有这两个头的非浏览器客户端仍须通过管理员会话和 CSRF 检查。登录及首次初始化不要求已有管理员会话，但同样拒绝明确的跨源请求。

TLS 在反向代理终止时，将代理的精确 IP 或 CIDR 填入现有 `trusted_proxies`。只有直连可信代理时，转发的协议、主机和来源才参与判断；代理必须覆盖客户端提供的 `X-Forwarded-Proto` / `X-Forwarded-Host`，并覆盖或正确追加来源 IP。推荐明确保留浏览器的 Host，禁止任意主机转发。示例（请替换为实际代理地址）：

```json
{
  "trusted_proxies": ["127.0.0.1/32", "::1/128"]
}
```

未配置代理信任时不接受客户端转发头。经可信代理识别为 HTTPS 的会话 Cookie 设置 `Secure`，同时保留 `HttpOnly` 和 `SameSite=Strict`。上线后如遇 403，请检查代理的 Host/协议配置，并刷新页面取得当前会话 Token，不要关闭来源或 CSRF 检查。

改变 Telegram Bot Token、授权用户或启用状态时，需要重新输入当前管理员密码；已启用 2FA 时还需要未消费的验证码或恢复码。没有启用 2FA 的账户可使用当前密码完成验证。普通设置更新不要求额外启用 2FA。

Web、控制端和 Agent 均限制请求体读取时间；认证表单在取得认证锁之前完成限长读取。读取超时与证书部署、软件更新的业务超时分开，不以短的统一响应超时中断这些长操作。

### 注册、指纹与身份保存

兼容旧参数 `-ca-fingerprint` 和 `ca_fingerprint`，其真实语义是 **主控控制端 TLS 叶证书的 SHA-256 指纹**，不是 CA 指纹。支持十六进制大小写、可选的 `SHA256:` 前缀及按字节冒号分隔格式。只比较 TLS 握手使用的第一张证书；附加证书不能建立信任。非空无效值立即失败，不降级跳过校验。

首次安装仍要求指纹。手动配置确需省略指纹时，只允许系统信任根和主机名校验均成功的 HTTPS；内部自签主控仍须提供正确指纹。注册 URL 必须是 HTTPS，固定端点拒绝所有重定向。主控叶证书被替换后，应重新生成安装命令；已注册 Agent 不会因此自动重新注册。

注册响应必须通过证书、CSR、本地私钥、签发 CA、有效期和 TLS 服务端用途校验，然后才保存身份。身份文件与清除一次性 Token 的配置保存作为一次可回滚的操作；提交失败时恢复已有身份和原配置，恢复失败则保留私有备份并报告其路径。若提交已全部完成、仅清理旧备份失败，Agent 会明确记录清理警告并使用完整的新身份，不重试已消费的 Token。并发消费同一注册 Token 只有一个请求可以成功，磁盘写入失败不会在内存中留下已消费状态。首次管理员初始化也在状态锁内检查并消费一次性 Token。

此次升级不改变已注册 Agent 的配置格式，不要求批量重新注册，不自动重新信任网络端点。原有 `allowed_server_cidrs` 的地址迁移规则继续适用。

完整生效需要更新主控和 Agent 的二进制。文件事务处理运行中的 I/O 失败与回滚；多文件替换并非跨文件的断电原子事务，主机断电或强制终止后应检查保留的备份与活动文件，恢复确认前不要手动 reload。

### 网站证书部署与 Nginx

Agent 在写文件前验证实际 `fullchain.pem` 的全部证书、叶证书与 `cert.pem` 的一致性、私钥、SAN、签名关系和非空 `ca.pem` 的一致性。保留私有 CA 和省略根证书的链，不强制某一家公共 CA；网站证书链与内部 mTLS CA 是两个不同用途的信任域。

部署按 Agent 串行执行：暂存全部文件、保存旧文件、替换、执行固定的 `nginx -t`，成功后才 reload。普通证书更新不执行 restart。校验或应用失败时恢复旧文件；应用失败或超时时另用独立的恢复操作验证旧配置并尝试恢复 reload，分别报告原始错误、文件回滚错误和服务恢复错误。无法确认恢复成功时仍返回失败；不要删除用于恢复的备份。

安装服务保留 `ProtectSystem=full`、`ProtectHome=true` 和 `PrivateTmp=true`。`ProtectSystem=full` 使 `/etc` 等只读，不阻止读取标准 `/opt` 安装中的证书；但 `nginx -t` 会打开配置引用的文件，隐藏的 home 路径、隔离的 `/tmp` 路径、不可写的自定义日志路径均可能使其失败。自定义部署需由管理员针对实际引用路径设置最小范围的读取/绑定或日志写入权限，或将引用文件移入可访问的固定目录；失败时应保留校验并拒绝部署，不全面关闭沙箱。此次仅以官方语义、代码及模拟执行验证这些分支，没有操作真实 Nginx 或 systemd。参见 [Nginx 参数说明](https://nginx.org/en/docs/switches.html) 和 [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)。

### 安装脚本与本地数据

生成的 Agent 安装命令先通过 sudo 进入 root 上下文，再创建随机的私有临时目录，下载、核对 Release 中安装脚本的 SHA-256 并执行。临时文件不经过可由其他用户写入的固定路径，下载或校验失败会终止，退出及信号路径会清理。正式版固定脚本和二进制版本；开发版仍使用 main/latest，脚本通过 HTTPS 获取。安装脚本设置 `umask 077`，配置内的名称、路径、URL、Token 使用 JSON 转义，不作为 Shell 代码执行。

Cloudflare / Telegram Token 仍按现有单用户、受保护主机的威胁模型明文保存在 `state.json`，网站私钥和账户密钥也以文件保存；状态、备份和私钥使用 `0600`，新建数据目录使用 `0700`。保护安装目录及历史备份，避免将配置、命令中的注册 Token 或私钥提交到仓库或集中日志。2FA 密钥加密不等于上述凭据已加密；也不能抵御能读取配置和进程的 root 或主机失陷。

主控当前验证 Agent 的内部 CA 签名和 IP SAN，Agent 验证主控客户端 CA 并使用来源 IP 白名单；尚无逐 Agent 证书/公钥固定及完整的证书撤销机制。删除 Agent 记录不等于吊销其证书。本次不静默固定首次连接中见到的身份，避免将现有端点冒充固化或使旧 Agent 批量失联；进一步实现需设计可信迁移和撤销流程。

更新器及安装流程的 SHA-256 文件和软件包来自同一 GitHub Release，只能检验一致性，**没有独立数字签名验证**，无法独立抵御 Release 发布账户被攻陷。主控对 Agent 的证书推送、更新和健康检查禁止跟随重定向，并限制响应大小。

来源限流与密码计算并发上限用于限制单一来源及资源消耗，不保证阻止分布式来源持续占满认证计算额度；账户级 OTP 限流仅在密码正确后生效，以免匿名错误密码直接锁住管理员。
