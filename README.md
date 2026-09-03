# oh-my-acme

单用户自用的 ACME 证书集中管理工具 —— 轻量、接近 `acme.sh` 的使用方式。

- **Server**：通过 Web UI 统一申请、续期通配符证书，并下发给多台 Agent。
- **Agent**：安装到目标服务器，接收证书、原子替换、校验 Nginx 配置并 `reload`。

## 特性

- Go 原生 ACME，支持通配符证书（`example.com` + `*.example.com`）
- DNS-01 验证，Cloudflare（`CF_Token` / `CF_Zone_ID` / `CF_Account_ID`）
- 自动 / 手动续期，Agent 下发失败可在 Web UI 手动重试
- 内部自签 CA 的 mTLS 通信，不依赖任何第三方 CA
- Server 与 Agent 通过 GitHub Release 的 `install.sh` 安装为 systemd 服务
- Web UI：Go 模板 + HTMX，单二进制，简体中文

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
