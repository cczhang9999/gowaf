# gowaf — 用 Go 写的迷你 WAF(反向代理式)

一个可运行的最小 WAF,用来演示 Go 在 WAF 项目中的**实际**用法。只依赖标准库,`go test -race` 通过。

```
客户端 ──► [ WAF 中间件 ] ──► httputil.ReverseProxy ──► 源站
            1 白名单 / 黑名单 / 自动封禁
            2 按 IP 令牌桶限流(429 + Retry-After)
            3 抽取 path / query / header / body(JSON 先解码)
            4 normalize(多重解码、去注释、小写)
            5 规则匹配 → 拦截(block)或仅记录(detect)
```

## 运行

```bash
go build -o gowaf .
./gowaf -listen :8080 -upstream http://127.0.0.1:9000

curl -i 'http://127.0.0.1:8080/?q=1+union+select+1'     # 403
curl -i 'http://127.0.0.1:8080/?q=hello'                 # 正常转发
curl    'http://127.0.0.1:8080/__waf/metrics'            # 仅本机可访问
```

常用参数:`-mode detect`(只记日志,新规则灰度用)、`-rps/-burst`、`-allow/-deny`(CIDR)、
`-ban-strikes/-ban-for`、`-max-body`、`-trust-xff`(仅前面确有可信代理时开启)。

## Web 管理控制台

### 启动 Web API 服务器

WAF 默认在 8081 端口启动 HTTP API 服务器，用于配置管理和监控：

```bash
./gowaf -listen :8080 -upstream http://127.0.0.1:9000 -api-addr :8081
```

### 启动前端管理控制台

```bash
cd web
pnpm install
pnpm dev
```

前端默认在 http://localhost:3000 访问，API 请求代理到 http://localhost:8081。

### Web 功能特性

- **仪表盘**: 实时查看请求数、拦截数、规则命中、限流数等指标
- **规则管理**: 查看、添加、编辑、删除 WAF 规则
- **配置管理**: 在线修改 WAF 配置(模式、限流、封禁等)
- **IP 列表**: 管理白名单和黑名单 IP
- **监控页**: 查看请求趋势、拦截分布、历史记录

## API 文档

### 规则管理接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/rules` | GET | 获取所有规则 |
| `/api/rules` | POST | 批量创建规则 |
| `/api/rules/{id}` | GET | 获取指定规则 |
| `/api/rules/{id}` | PUT | 更新指定规则 |
| `/api/rules/{id}` | DELETE | 删除指定规则 |

### 配置管理接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/config` | GET | 获取当前配置 |
| `/api/config` | PUT | 更新配置 |

### IP 列表接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/allow` | GET | 获取白名单 |
| `/api/allow` | POST | 添加到白名单 |
| `/api/allow` | DELETE | 从白名单移除 |
| `/api/deny` | GET | 获取黑名单 |
| `/api/deny` | POST | 添加到黑名单 |
| `/api/deny` | DELETE | 从黑名单移除 |

### 监控接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/metrics` | GET | 获取实时指标 |

### 健康检查接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/healthz` | GET | WAF 健康检查 |
| `/api/bastion/healthz` | GET | 堰垒机健康检查 |

### 堰垒机(SSH)管理接口

> 启动时需加上 `-ssh` 参数。如未启用 SSH 堰垒机,这些接口返回 `503 Service Unavailable`
> (而非 404),错误信息提示需加 `-ssh` 参数。

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/bastion/users` | GET | 获取所有用户 |
| `/api/bastion/users` | POST | 创建用户 |
| `/api/bastion/users/{id}` | GET | 获取指定用户 |
| `/api/bastion/users/{id}` | PUT | 更新用户 |
| `/api/bastion/users/{id}` | DELETE | 删除用户 |
| `/api/bastion/assets` | GET | 获取所有资产 |
| `/api/bastion/assets` | POST | 创建资产 |
| `/api/bastion/assets/{id}` | GET | 获取指定资产 |
| `/api/bastion/assets/{id}` | PUT | 更新资产 |
| `/api/bastion/assets/{id}` | DELETE | 删除资产 |
| `/api/bastion/sessions` | GET | 获取所有会话 |
| `/api/bastion/sessions/{id}/recording` | GET | 下载会话录像 |
| `/api/bastion/sessions/{id}` | GET | 获取指定会话详情 |
| `/api/bastion/audit` | GET | 获取审计日志 |
| `/api/bastion/banned` | GET | 获取禁止命令列表 |
| `/api/bastion/banned` | POST | 添加禁止命令 |
| `/api/bastion/config` | GET | 获取堰垒机配置 |
| `/api/bastion/config` | PUT | 更新堰垒机配置 |

### 用户持久化(users1 表)

堡垒机用户默认只存在内存里,进程重启即丢。加上 `-mysql-dsn` 后,
`/api/bastion/users` 的增删改查直接落到 MySQL 的 **`users1`** 表:

```bash
# 独立堡垒机
./bastion -api-listen :8081 \
  -mysql-dsn 'user:pass@tcp(127.0.0.1:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local'

# WAF + 堡垒机管理面(同一个 API 地址)
./gowaf -listen :8080 -upstream http://127.0.0.1:9000 -api-addr :8081 \
  -mysql-dsn 'user:pass@tcp(127.0.0.1:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local'
```

建表脚本:`sql/init_users.sql`(启动时 GORM `AutoMigrate` 也会自动建表)。
接口里的 `{id}` 既可以是 `username`,也可以是 `users1.id`;`GET /api/bastion/healthz`
返回的 `user_store` 会显示当前是 `mysql(users1)` 还是 `memory`。

| users1 列 | 接口字段 | 说明 |
|---|---|---|
| `id` | `id` | 主键,`/users/{id}` 可直接用 |
| `username` | `username` | 唯一,`/users/{username}` 也可用 |
| `password` | — | bcrypt hash,任何响应里都不返回 |
| `role` | `role` | `admin` / `user` / `auditor` |
| `public_key` | `public_key` | SSH 公钥登录 |
| `assets` | `assets` | JSON 数组;空数组表示可访问全部资产 |
| `comment` | `comment` | 备注 |
| `created_at` / `updated_at` | `created_at` | 时间戳 |

> 表名固定是 `users1`。同一个库里可能还有业务方的 `users`(`id/name/email`),
> 两者互不相干,不要混用。

### 启动 SSH 堰垒机

```bash
# 方式 1: 在 WAF 之外同时启用 SSH 堰垒机
./gowaf -listen :8080 -upstream http://127.0.0.1:9000 -ssh -ssh-listen :2222 -api-addr :8081

# 方式 2: 仅运行 SSH 堰垒机(不启用 WAF 代理)
go build -o bastion ./cmd/bastion
./bastion -api-listen :8081
```

方式 2 的独立堰垒机二进制也在 `/api/bastion/` 下提供完整的管理接口,
前端开发控制台代理自动转发 `/api` 到 `http://localhost:8081`。

## 自定义规则 + 热加载

```bash
./gowaf -rules rules.example.json &
kill -HUP $!          # 改完规则文件后重载;编译失败则保留旧规则
```

## Go 的特性在这里各自解决什么问题

| WAF 里的需求 | Go 的做法 | 代码位置 |
|---|---|---|
| 反向代理、转发 | `net/http/httputil.ReverseProxy`,用 `Rewrite` + `SetXForwarded` 覆盖客户端伪造的 XFF | main.go |
| 每个请求独立处理 | `net/http` 每连接一个 goroutine,处理逻辑写成同步代码即可 | waf.go `Handler` |
| 规则不能被 ReDoS 打死 | `regexp` 基于 RE2,保证线性时间 | rules.go |
| 规则热更新,读路径不加锁 | `atomic.Pointer[[]Rule]` 整体替换 + `SIGHUP` | waf.go `SetRules` / main.go |
| 高并发限流 | 32 分片 + 每片一把 `sync.Mutex`,不同 IP 基本不竞争 | ratelimit.go |
| 防内存被撑爆 | 后台 goroutine 定期 GC 过期桶;IPv6 按 /64 归并 | ratelimit.go / waf.go `Run` |
| IP 白/黑名单 | `net/netip`(值类型、可作 map key、无堆分配) | waf.go |
| 结构化审计日志 | `log/slog` JSON | main.go |
| 防慢速攻击 | `http.Server` 的 `ReadHeaderTimeout` 等超时 | main.go |
| 平滑发布 | `signal.NotifyContext` + `srv.Shutdown` | main.go |
| 验证并发正确性、性能 | `go test -race`、`testing.B` 基准 | waf_test.go |
| 部署 | 编译成单个静态二进制 | — |

## 内置的绕过防御(测试里都有对应用例)

- 多重 URL 编码(`%2527`)、`+` 当空格
- 非法 `%zz` 序列:宽容解码,不会因为一个坏序列让后面的 payload 躲过
- SQL 注释穿插(`UNION/**/SELECT`)
- JSON 里的 `'` 转义:先按 JSON 解码再检测
- 请求体读完后回填 `r.Body`,上游仍能完整读取
- 超过 `-max-body` 直接 413,不把大包体读进内存
- `Authorization` 头不参与检测、不进日志

## 基准(2 vCPU 沙箱,仅供参考)

- 正常请求(3 个字段 × 16 条规则全部未命中):约 39 µs/次
- 攻击请求(较早命中):约 3.4 µs/次

规则越多,干净流量越慢(每条规则都要扫一遍)。规则上百条后需要做预过滤(先用 `strings.Contains` 或
Aho-Corasick 筛关键字,再跑正则)。

## 生产环境配置

### 使用配置文件

推荐使用 YAML 配置文件管理所有配置项:

```bash
# 复制配置示例
cp config.yaml.example config.yaml

# 使用配置文件启动
./gowaf -config config.yaml
```

配置优先于 CLI 默认值,但 CLI flags 会覆盖配置文件中的值。

### 限流配置

```yaml
rate_limit:
  enabled: true
  rps: 50.0                    # 每 IP 每秒请求数
  burst: 100                   # 令牌桶突发容量
  strategy: "per_ip"           # per_ip / per_path / per_user
  
  # 限流例外路径
  path_whitelist:
    - "/api/healthz"
    - "/api/metrics"
  
  # 按路径差异化限流
  path_rules:
    - path: "/api/*"
      rps: 30.0
      burst: 60
    - path: "/login"
      rps: 10.0
      burst: 20
  
  # 自动封禁
  auto_ban:
    enabled: true
    strikes: 5                 # 1分钟内违规次数
    window: "1m"              # 时间窗口
    duration: "10m"            # 封禁时长
```

详细配置说明见 [config.yaml.example](config.yaml.example)

## 生产环境文档

- [部署指南](docs/deployment-guide.md) - Docker、Kubernetes、systemd 部署
- [安全加固指南](docs/security-hardening.md) - 网络安全、访问控制、审计
- [性能调优指南](docs/performance-tuning.md) - 限流、连接池、内核参数
- [监控与可观测性](docs/monitoring.md) - Prometheus、Grafana、日志分析
- [API 文档](docs/openapi.yaml) - OpenAPI 3.0 规范 (Swagger UI)

## 已知局限(这不是生产级 WAF)

- 正则规则必然有误报/漏报;上线前先用 `-mode detect` 跑一段时间看日志
- 没有解析 `multipart/form-data`(整体当文本检测),上传接口建议用白名单路径或单独处理
- 不检查响应内容,没有 TLS 终止(可用 `ListenAndServeTLS` 或放在 Nginx/LB 后面)
- 没有语义级检测(libinjection 那类 tokenizer),也没有 OWASP CRS 那种异常评分机制
- 需要真正的生产方案时,可以看 Go 写的 OWASP Coraza(兼容 ModSecurity 规则语法和 CRS),
  它同样大量用到上面这些 Go 特性
