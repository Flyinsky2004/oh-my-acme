# oh-my-acme

单用户自用的 ACME 证书集中管理工具 —— 轻量、接近 `acme.sh` 的使用方式。

- **Server**：通过 Web UI 统一申请、续期通配符证书，并下发给多台 Agent。
- **Agent**：安装到目标服务器，接收证书、原子替换、校验 Nginx 配置并 `reload`。

## 特性

- Go 原生 ACME，支持通配符证书（`example.com` + `*.example.com`）
- DNS-01 验证，Cloudflare（`CF_Token` / `CF_Zone_ID` / `CF_Account_ID`）
- 自动 / 手动续期，Agent 下发失败可在 Web UI 手动重试
- 手动下发前可选择本次同步的目标 Agent，支持全选 / 取消全选；自动续期仍下发到全部配置目标
- 内部自签 CA 的 mTLS 通信，不依赖任何第三方 CA
- Server 与 Agent 通过 GitHub Release 的 `install.sh` 安装为 systemd 服务
- Web UI：Go 模板 + HTMX + 已编译 CSS，单二进制，简体中文，完全离线

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
