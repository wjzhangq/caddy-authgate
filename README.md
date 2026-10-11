# caddy-authgate

AuthGate 是一个 [Caddy](https://caddyserver.com) v2 HTTP 处理器插件，用邮箱验证码与 API key 为任意站点加上一道统一的登录门禁。

- **验证码登录**：内置登录页，用户输入用户名，验证码经外部发码服务发送到 `用户名@域名`，验证后写入 Cookie
- **Bearer key**：脚本与服务间调用使用 `Authorization: Bearer sk-…`
- **管理页面**：浏览器访问 `/authgate/` 即可管理自己的 key；管理员还可查看所有用户、增删用户及其 key
- **用户管理**：管理员通过 HTTP 接口增删用户；用户自助管理自己的 key；用户文件为纯文本，可手工编辑并热加载
- **header 注入**：认证通过后向上游注入 `X-Auth-User`、`X-Is-Admin`、`X-Auth-Method`，并剥离客户端伪造的同名 header 与凭证

---

## 快速开始

### 1. 获取二进制

从 [Releases](https://github.com/wjzhangq/caddy-authgate/releases) 下载对应平台的二进制，并用 `SHA256SUMS` 校验：

| 平台 | 文件 |
|---|---|
| Linux x86_64 / ARM64 | `caddy-authgate-linux-amd64`、`caddy-authgate-linux-arm64` |
| macOS Intel / Apple Silicon | `caddy-authgate-darwin-amd64`、`caddy-authgate-darwin-arm64` |
| Windows x86_64 / ARM64 | `caddy-authgate-windows-amd64.exe`、`caddy-authgate-windows-arm64.exe` |


```bash
sha256sum -c SHA256SUMS --ignore-missing
chmod +x caddy-authgate-linux-amd64
./caddy-authgate-linux-amd64 list-modules | grep authgate   # 应输出 http.handlers.authgate
```

或自行构建（见[构建](#构建)）：

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/wjzhangq/caddy-authgate
```

### 2. 最小 Caddyfile

```caddyfile
{
	authgate_file         /etc/caddy/authgate/users.txt
	authgate_admin        alice
	authgate_domain       example.com
	authgate_sendcode_url https://mail.example.com/send
}

app.example.com {
	authgate
	reverse_proxy 127.0.0.1:3000
}
```

用户文件不存在时会自动创建（权限 `0600`）。

### 3. 创建首个管理员并登录

1. 在 `authgate_admin` 中写上自己的用户名（如 `alice`）。配置中的管理员无需出现在用户文件里即可登录。
2. 启动 Caddy：`caddy run --config Caddyfile`。
3. 浏览器打开 `https://app.example.com`，看到登录页，输入 `alice`，点击“发送验证码”。
4. 在 `alice@example.com` 邮箱中收到验证码，输入后登录。
5. 打开 `https://app.example.com/authgate/` 进入[管理页面](#管理页面)，可添加用户、为用户生成 key。也可以用接口直接创建：

```bash
curl -H "Authorization: Bearer $ADMIN_KEY" "https://app.example.com/authgate/user/add?user=bob"
# {"created":true,"key":"sk-68e8c800…","user":"bob"}
```

本地试用可以使用仓库自带的模拟发码服务，它会把验证码打印在终端：

```bash
go run ./scripts/mocksend -addr 127.0.0.1:9999
# 并将 authgate_sendcode_url 设为 http://127.0.0.1:9999/
```

---

## 构建

需要 Go（版本见 `go.mod`）与 [xcaddy](https://github.com/caddyserver/xcaddy)。

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 使用已发布版本
xcaddy build --with github.com/wjzhangq/caddy-authgate

# 使用本地源码
xcaddy build --with github.com/wjzhangq/caddy-authgate=.

# 指定 Caddy 版本（最低 v2.8）
xcaddy build v2.10.2 --with github.com/wjzhangq/caddy-authgate=.
CADDY_VERSION=v2.10.2 xcaddy build --with github.com/wjzhangq/caddy-authgate=.

# 交叉编译 Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 xcaddy build \
  --with github.com/wjzhangq/caddy-authgate=. \
  --output dist/caddy-authgate-linux-arm64
```

或使用 Makefile：`make build`（本机）、`make build-linux`（Linux amd64 + arm64）、`make build-all`（Linux / macOS / Windows 的 amd64 + arm64）。

---

## 配置参考

### 全局选项

写在 Caddyfile 顶部的全局选项块中，对所有站点生效。值中可以使用 `{env.NAME}` 引用环境变量（启动时替换）。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `authgate_file <path>` | —（必填） | 用户文件路径，不存在时自动创建 |
| `authgate_sendcode_url <url>` | —（必填） | 发码服务地址，见[发码服务](#发码服务) |
| `authgate_sendcode_header <name> <value>` | — | 调用发码服务时附加的 header，可出现多次 |
| `authgate_admin <user...>` | — | 管理员用户名，空格或逗号分隔，可出现多次 |
| `authgate_domain <domain>` | `lenovo.com` | 邮箱域名，验证码发送到 `用户名@domain` |
| `authgate_token_ttl <duration>` | `1h` | 登录 token 与 Cookie 有效期 |
| `authgate_secret <string>` | 自动生成 | token 签名密钥，至少 32 字节；未配置时读取或生成 `<authgate_file>.secret` |
| `authgate_code_ttl <duration>` | `5m` | 验证码有效期 |
| `authgate_code_interval <duration>` | `30s` | 同一用户发送间隔，最小 `30s` |
| `authgate_cookie_name <name>` | `authgate_token` | Cookie 名称 |
| `authgate_cookie_domain <domain>` | — | Cookie 的 Domain 属性，多个子域共享登录态时设置，如 `.example.com` |
| `authgate_max_keys <n>` | `20` | 每个用户的 key 数量上限 |

### 站点指令

```caddyfile
authgate [auto|web|api] {
	mode              auto|web|api
	bypass            /healthz /static/* /favicon.ico
	strip_credentials on|off
}
```

| 子指令 | 默认值 | 说明 |
|---|---|---|
| `mode` | `auto` | 未认证时的响应方式与可用凭证，见[模式判定](#模式判定)；也可写成 `authgate api` 简写 |
| `bypass <path...>` | — | 免认证路径，语法同 Caddy `path` 匹配器，可出现多次 |
| `strip_credentials` | `on` | 转发上游前删除 `Authorization` 与 AuthGate Cookie |

`authgate` 指令默认排在 `basic_auth` 之后，先于 `respond`、`reverse_proxy`、`file_server` 等执行，无需写 `route` 或 `order`。

### 示例

**auto：浏览器与脚本混用**

```caddyfile
app.example.com {
	authgate {
		bypass /healthz /static/*
	}
	reverse_proxy 127.0.0.1:3000
}
```

**api：纯接口服务，只接受 Bearer key**

```caddyfile
api.example.com {
	authgate api
	reverse_proxy 127.0.0.1:4000
}
```

**按路径混合**

```caddyfile
portal.example.com {
	route /api/* {
		authgate api
		reverse_proxy 127.0.0.1:5000
	}
	route {
		authgate web
		reverse_proxy 127.0.0.1:5001
	}
}
```

完整示例见 [`examples/Caddyfile`](examples/Caddyfile)。

### 发码服务

AuthGate 不直接发邮件，而是调用 `authgate_sendcode_url`：

```http
POST <authgate_sendcode_url>
Content-Type: application/json; charset=utf-8
<authgate_sendcode_header ...>

{"email":"alice@example.com","subject":"登录验证码","html":"<p>您的登录验证码为 <b>123456</b>，5 分钟内有效。</p>..."}
```

超时 10 秒，返回 2xx 视为成功。失败时接口返回 `502 send_failed`，且不进入发送冷却。

---

## 用户文件

每行一个 key，格式为 `<key>:<user>`，按第一个 `:` 分隔：

```text
# AuthGate 用户文件
sk-68e8c80012ab34cd56ef7890:alice
sk-68e8c8a1ffee00112233aabb:alice
sk-68e8c9020a1b2c3d4e5f6a7b:bob
legacy-token-for-ci-123:ci-bot
```

| 规则 | 说明 |
|---|---|
| 注释与空行 | `#` 开头为注释，空行忽略；程序写入时保留注释与原有顺序，新行追加在末尾 |
| 用户名 | `^[a-z0-9][a-z0-9._-]{0,63}$`，加载时转小写 |
| key | 不含空白与 `:`，长度 8–128。标准格式为 `sk-` + 8 位 hex 时间戳 + 16 位 hex 随机数；非标准 key 可用，但会输出 warn 日志 |
| 重复 key | 启动时报错退出；热加载时保留旧数据并记录 error 日志 |
| 非法行 | 忽略并输出 warn 日志 |
| 权限 | 文件包含明文 key，请保持 `0600` 并限制目录访问；程序以“临时文件 + fsync + rename”原子写入，新文件权限为 `0600` |
| 热加载 | 每 5 秒检查一次修改时间，变化后自动重载，无需 reload Caddy |

用户“存在”的定义：用户文件中至少有一个 key，**或**在 `authgate_admin` 列表中。删除用户即删除其全部 key，已签发的 Cookie 随之失效。

---

## 认证方式

### Web 登录流程

```text
浏览器                         AuthGate                        发码服务
  │ GET /page                     │                               │
  │──────────────────────────────▶│ 无有效 Cookie                  │
  │◀──────────── 401 + 登录页 ─────│                               │
  │ POST /authgate/code/send      │                               │
  │──────────────────────────────▶│ POST sendcode_url ───────────▶│ ─▶ 邮件
  │◀────────── 200 resend_after ──│◀──────────── 2xx ─────────────│
  │ POST /authgate/code/valid     │                               │
  │──────────────────────────────▶│ 校验验证码，签发 token         │
  │◀──── 200 + Set-Cookie ────────│                               │
  │ location.reload()             │                               │
  │ GET /page (Cookie)            │                               │
  │──────────────────────────────▶│ 注入 X-Auth-User ──▶ 上游       │
```

登录页在原 URL 以 401 返回，登录成功后刷新即可回到原页面。Token 为 `v1.<payload>.<HMAC-SHA256>`，Cookie 属性为 `HttpOnly`、`SameSite=Lax`、`Path=/`，HTTPS 下附加 `Secure`。

### Bearer key

```bash
curl -H "Authorization: Bearer sk-68e8c80012ab34cd56ef7890" https://api.example.com/v1/items
```

携带 `Authorization` header 时**只**校验 Bearer key，不会回退到 Cookie。同一 IP 每分钟超过 60 次无效 Bearer 将返回 `429 rate_limited`。

### 模式判定

凭证提取：

| 模式 | 携带 Authorization | 未携带 Authorization |
|---|---|---|
| `auto` / `web` | 校验 Bearer | 校验 Cookie |
| `api` | 校验 Bearer | 未认证 |

未认证时的响应：

| mode | 条件 | 响应 |
|---|---|---|
| api | 任意 | 401 JSON |
| web | 携带 Authorization | 401 JSON |
| web | 其他 | 401 + 登录页 |
| auto | 携带 Authorization 或 `X-Requested-With: XMLHttpRequest` | 401 JSON |
| auto | GET/HEAD 且 `Accept` 含 `text/html` | 401 + 登录页 |
| auto | 其他 | 401 JSON |

401 JSON 均带 `WWW-Authenticate: Bearer realm="authgate"`。

---

## 管理页面

在任意启用了 `authgate` 的站点上用浏览器访问 `/authgate/`（`/authgate` 会 301 跳转过去）：

- 未登录时显示登录页，登录成功后自动进入管理页。
- **所有用户**：“我的 key”区域列出自己的全部 key（完整显示，可一键复制）及创建时间，可添加或删除 key；普通用户至少保留一个 key。
- **管理员**额外显示“用户管理”区域：
  - 列出所有用户（含仅在 `authgate_admin` 中配置的管理员），标注管理员身份与 key 数量；
  - 添加用户（自动生成首个 key 并提示）、删除用户（配置中的管理员与自己不可删除）；
  - 点击“管理 key”展开该用户的 key 列表，可为其添加或删除 key。

页面所有操作都通过下文的接口以 Cookie 方式调用（同源 POST，满足 CSRF 规则），与登录页使用相同的 CSP，不加载外部资源。

> 页面会完整显示 key，请注意屏幕共享与截图。

---

## 后端集成

认证通过后，上游收到以下 header：

| Header | 值 |
|---|---|
| `X-Auth-User` | 用户名 |
| `X-Is-Admin` | `true` / `false` |
| `X-Auth-Method` | `web`（Cookie）/ `api`（Bearer） |

客户端发来的同名 header 在任何路径（包括 `bypass` 路径）上都会被删除。

> **后端只应信任来自 Caddy 的请求。** 请让后端只监听 `127.0.0.1` 或内网地址，或在防火墙上限制来源，否则攻击者可以绕过 Caddy 直接伪造这些 header。

---

## 接口参考

所有接口位于每个启用了 `authgate` 的站点的 `/authgate/` 路径下，不受 `mode` 与 `bypass` 影响。

- 参数可放在 query、表单（`application/x-www-form-urlencoded` / `multipart/form-data`）或 JSON body 中。
- 响应为 `application/json; charset=utf-8`，带 `Cache-Control: no-store`。
- 需登录的接口同时接受 Bearer 与 Cookie。
- **CSRF**：以 Cookie 认证调用变更类接口（标注“变更”）时，必须为 POST，且 `Origin`（缺省取 `Referer`）的 host 等于请求 Host，否则 `403 csrf_rejected`。Bearer 调用不受此限制。

以下示例统一使用 Bearer：

```bash
H="Authorization: Bearer $KEY"; BASE=https://app.example.com/authgate
```

### `user/add?user=` — 管理员，变更

```bash
curl -H "$H" "$BASE/user/add?user=bob"
```

- 新建：`201 {"user":"bob","key":"sk-…","created":true}`
- 已存在：`200 {"user":"bob","key":"<第一个 key>","created":false}`；仅在管理员列表中且无 key 的用户会新建 key 并返回 201
- `user` 也可写成 `bob@<authgate_domain>`

### `user/delete?user=` — 管理员，变更

```bash
curl -X POST -H "$H" -d user=bob "$BASE/user/delete"
# {"user":"bob","deleted":true,"keys_removed":2}
```

错误：`404 user_not_found`、`409 user_is_admin`（配置中的管理员）、`409 cannot_delete_self`。

### `user/list` — 管理员

```bash
curl -H "$H" "$BASE/user/list"
# {"users":[{"user":"alice","is_admin":true,"key_count":0},{"user":"bob","is_admin":false,"key_count":2}]}
```

按用户名排序，包含仅在管理员列表中的用户。

key 接口（`key/list`、`key/add`、`key/delete`）默认操作当前用户自己的 key；**管理员**可额外传 `user=` 参数操作其他用户的 key（目标用户不存在时返回 `404 user_not_found`，普通用户指定他人时返回 `403 forbidden`）。

### `key/list[?user=]` — 登录

```bash
curl -H "$H" "$BASE/key/list"
# {"user":"bob","keys":[{"key":"sk-68e8c800…","created_at":"2025-10-10T08:00:00Z"},{"key":"legacy-…","created_at":null}]}
```

### `key/add[?user=]` — 登录，变更

```bash
curl -X POST -H "$H" "$BASE/key/add"
# 201 {"user":"bob","key":"sk-…"}
```

超过 `authgate_max_keys` 时返回 `409 key_limit_reached`。

### `key/delete?key=[&user=]` — 登录，变更

```bash
curl -X POST -H "$H" -d key=sk-68e8c800… "$BASE/key/delete"
# {"user":"bob","key":"sk-68e8c800…","deleted":true}
```

普通用户只能删除自己的 key。错误：`404 key_not_found`、`409 last_key`（普通用户不能删除最后一个 key；管理员可以）。

### `me` — 登录

```bash
curl -H "$H" "$BASE/me"
# {"user":"bob","is_admin":false,"method":"api","expires_at":null}
```

Cookie 认证时 `method` 为 `web`，`expires_at` 为 token 过期时间。

### `code/send?user=` — 匿名，仅 POST

```bash
curl -X POST -d user=bob "$BASE/code/send"
# {"user":"bob","email":"bob@example.com","expires_in":300,"resend_after":30}
```

错误：`400 invalid_param`、`404 user_not_found`、`429 too_frequent`（同一用户发送间隔内）/ `429 rate_limited`（同一 IP 每分钟 10 次），均带 `retry_after`；`502 send_failed`（含 `upstream_status`）。

### `code/valid?user=&code=` — 匿名，仅 POST

```bash
curl -c cookies.txt -X POST -d user=bob -d code=123456 "$BASE/code/valid"
# {"user":"bob","is_admin":false,"expires_in":3600}   + Set-Cookie
```

错误：`400 invalid_code`（含 `remaining_attempts`）、`410 code_expired`（过期、已使用或不存在）、`429 too_many_attempts`（错误 5 次后作废）、`429 rate_limited`（同一 IP 每分钟 30 次）。

### `logout` — 匿名

```bash
curl -X POST "$BASE/logout"
# {"logout":true}   + 清除 Cookie
```

浏览器 GET 且 `Accept` 含 `text/html` 时 302 跳转到 `/`。

---

## 错误码

错误响应体：`{"error":"<code>","message":"<中文提示>", ...}`。带 `retry_after`（秒）时同时设置 `Retry-After` header。

| HTTP | error | 说明 |
|---|---|---|
| 400 | `invalid_param` | 参数缺失或格式错误 |
| 400 | `invalid_code` | 验证码错误，附 `remaining_attempts` |
| 401 | `unauthorized` | 未登录或凭证无效 |
| 403 | `forbidden` | 非管理员调用管理员接口 |
| 403 | `csrf_rejected` | Cookie 认证的变更请求未通过来源校验 |
| 404 | `not_found` | 接口不存在 |
| 404 | `user_not_found` | 用户不存在 |
| 404 | `key_not_found` | key 不存在或不属于当前用户 |
| 405 | `method_not_allowed` | 请求方法不支持 |
| 409 | `user_is_admin` | 不能删除配置中的管理员 |
| 409 | `cannot_delete_self` | 不能删除自己 |
| 409 | `key_limit_reached` | key 数量达到上限 |
| 409 | `last_key` | 普通用户不能删除最后一个 key |
| 410 | `code_expired` | 验证码过期、已使用或不存在 |
| 429 | `too_frequent` | 发送验证码过于频繁，附 `retry_after` |
| 429 | `rate_limited` | IP 限流，附 `retry_after` |
| 429 | `too_many_attempts` | 验证码错误次数过多，已作废 |
| 500 | `storage_error` | 用户文件写入失败 |
| 502 | `send_failed` | 发码服务调用失败，附 `upstream_status` |

---

## 安全说明

- **文件权限**：用户文件与 `<file>.secret` 均为 `0600`，请确保只有运行 Caddy 的用户可读写其所在目录。
- **secret**：未配置 `authgate_secret` 时自动生成 `<authgate_file>.secret`，重启后 token 依然有效；删除该文件会使所有已登录用户失效。多台机器或希望集中管理时，用 `authgate_secret {env.AUTHGATE_SECRET}` 配置至少 32 字节的随机串（如 `openssl rand -hex 32`）。
- **CSRF**：Cookie 为 `SameSite=Lax`；以 Cookie 认证调用变更类接口必须为同源 POST。验证码接口仅接受 POST。
- **限流**：`code/send` 10 次/分钟/IP、`code/valid` 30 次/分钟/IP、无效 Bearer 60 次/分钟/IP；验证码错误 5 次即作废。位于反向代理或 CDN 之后时，请配置 Caddy 的 `trusted_proxies`，以便识别真实客户端 IP。
- **单实例限制**：验证码、冷却与限流状态保存在内存中，Caddy reload 时保留，但不在多个实例间共享。多实例部署请保持会话粘性或只在单实例上开放登录。
- **key 明文存储**：key 以明文保存在用户文件中，与 SSH `authorized_keys` 类似，请按机密文件对待；日志中只输出掩码形式（`sk-68e8…7890`），验证码与 token 不写入日志。
- **登录页**：使用严格的 CSP（`default-src 'none'`，仅允许内联样式/脚本与同源请求）和 `frame-ancestors 'none'`，不加载任何外部资源。

---

## 开发

### 目录结构

```text
├── module.go            模块注册、指令注册、默认顺序
├── caddyfile.go         全局选项与站点指令解析
├── core.go              全局配置、共享状态 Core 与 UsagePool
├── handler.go           Provision / Validate / Cleanup / ServeHTTP 管线
├── api.go               /authgate/* 接口
├── respond.go           JSON 响应与错误码
├── loginpage.go         登录页与管理页渲染
├── loginpage/           内置登录页与管理页（go:embed）
├── internal/
│   ├── store/           用户文件解析、索引、原子写入、热加载
│   ├── code/            验证码生成、冷却、校验、尝试次数
│   ├── token/           HMAC token 签发与校验、密钥加载
│   ├── keygen/          key 生成与时间戳解析
│   ├── ratelimit/       IP 级令牌桶限流
│   └── mailer/          调用 sendcode_url
├── examples/Caddyfile   示例配置
├── scripts/e2e.sh       端到端测试
├── scripts/mocksend/    模拟发码服务
└── .github/workflows/   CI 与发布
```

`internal/` 下各包不依赖 Caddy，可独立测试；根包测试会在进程内启动真实的 Caddy 并覆盖验收用例。

### 常用命令

```bash
make test        # go vet + go test -race -cover ./...
make lint        # golangci-lint run
make build       # xcaddy 构建 dist/caddy
make build-linux # 构建 dist/caddy-authgate-linux-{amd64,arm64}
make build-all   # 构建 Linux / macOS / Windows 全部平台
make e2e         # 构建并运行 scripts/e2e.sh（需要 curl、jq）
```

基准测试（10 万 key）：

```bash
go test -run xxx -bench . ./internal/store/ .
```

参考结果（4 核虚拟机）：Bearer 认证完整处理约 3 µs/请求，key 查找约 0.25 µs，10 万 key 常驻堆内存约 18 MiB，新增 key（整文件原子重写）约 100 ms。

### 发布流程

1. main 分支 CI 全绿。
2. 更新 README 中的版本说明。
3. 打 `vX.Y.Z` 形式的 tag 并推送：`git tag v1.0.1 && git push origin v1.0.1`。只有这种严格的三段版本号 tag 才会触发发布，`v1.0`、`v1.0.1-rc1` 等不会。
4. GitHub Actions 自动构建 Linux / macOS / Windows（amd64 + arm64）共 6 个二进制与 `SHA256SUMS` 并创建 Release；下载后执行 `list-modules` 确认包含 `http.handlers.authgate`。

推送 main 分支与 PR 只运行测试与构建（产物可在 Actions 的 artifacts 中下载），不会发布 Release。

---

## License

[MIT](LICENSE)
