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
