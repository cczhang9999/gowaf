# GoWAF 生产就绪度分析与 API 限流落地设计

> 基线：仓库当前 HEAD（`503b2589`）+ 工作区改动。结论基于对源码的逐文件阅读、`go vet` / `go build` / `go test -race` 实测。
>
> 实测结果：`go vet ./...` 干净，`go build ./...` 通过，`go test -race ./...` 全绿
> （`gowaf`、`gowaf/bastion`、`gowaf/internal/middleware`、`gowaf/models`）。
> **功能可用 ≠ 生产可用**——下面的差距几乎全部来自"实现了但没接线""默认配置 fail-open""单机内存态"三类问题。

---

## 已落地的修复（第 1 批：安全边界）

> 状态：✅ 已实现。`go vet ./...` 干净、`go build ./...` 通过、`go test -race ./...` 全绿，
> 并做了运行时冒烟验证（HTTP 状态码与进程退出码实测）。

| 原编号 | 修复内容 | 关键改动 | 冒烟验证结果 |
|---|---|---|---|
| P0#1 | 独立堡垒机 API 零认证 | 新增 `-api-token` / `GOWAF_API_TOKEN` / `-insecure-no-auth`；挂载 `middleware.BearerToken`；无 token 拒绝启动；默认监听改 `127.0.0.1:8081` | 无 token 启动 → exit 1；`/api/bastion/users` 无头 → 401，错 token → 403，对 token → 200 |
| P0#2 | WAF 内嵌 API fail-open | `enabled=true && token==""` 时启动即 fatal | 实测 exit 1 并打印明确修复指引 |
| 场景 A | 管理 API **认证前**限流 + 失败锁定 | 限流中间件移到认证之外；新增 `authBanner`（5 次/1 分钟 → 封 15 分钟） | 第 5 次失败后返回 `429` + `Retry-After: 900`；锁定期内正确 token 同样被拒 |
| 场景 H | `apiLimiter` 无 GC（内存泄漏） | 新增 `APIServer.Run(ctx)`，统一回收 API 限流桶与认证失败计数 | 进程内周期任务已接入 `main.go` |
| P0#8 | 录像路径穿越 | `StartSession` 接入 `sanitizeUsername` + `filepath.Clean` 前缀校验 | 单测：`../../../../tmp/pwned` 无法逃出录像目录 |
| P0#10 | `HasUser` 吞错 → 创建覆盖已有用户 | 新增 `HasUserErr`，区分「不存在」(`store.ErrUserNotFound`) 与「查询失败」；写路径全部改用 | 创建用户/初始化管理员遇到 DB 错误返回 5xx / fatal，不再静默覆盖 |
| P0#4 | 明文 DSN 进 git | `config.yaml` 移出版本控制并加入 `.gitignore`，权限改 `0600`；新增 `GOWAF_MYSQL_DSN` 环境变量（优先级高于 YAML） | `git ls-files config.yaml` 已为空 |
| — | 前端无 Token 支持（启用认证会打不开控制台） | axios 请求拦截器自动附带 Token；401/403 时提示输入并重试一次 | 见 `web/src/api/index.ts` |

**修复过程中额外发现的一个真实缺陷**：`BearerToken("")` 会让 `Authorization: Bearer `（空凭证）
与空 secret 常量时间相等而**通过认证**。已在中间件构造期对空 token 直接拒绝全部请求，
并用单测 `TestBearerTokenEmptyTokenRejects` 固化该语义。

**仍需人工完成的两件事**（涉及外部凭据，无法由代码完成）：

1. **轮换数据库口令**——旧口令已存在于 git 历史中，移除文件跟踪**不等于**口令安全。
   建议 `git filter-repo` 清理历史后立即改密。
2. **配置控制台 Token**——`config.yaml` 已生成一个随机 token，控制台首次访问会提示粘贴；
   生产环境请替换为自己的强随机值，并优先用 `GOWAF_API_TOKEN` 环境变量注入。

---


## 0. 一句话结论

这是一个**架构正确、工程质量不错、但安全边界和状态管理尚未闭环**的教学级 WAF：

- 数据面（反向代理 + 规则引擎 + 令牌桶）设计思路是对的，`atomic.Pointer` 热更新、RE2 防 ReDoS、32 分片锁、`sync.Pool` 都是加分项。
- **真正阻塞上生产的是三件事**：① 管理面/堡垒机面默认**无认证或 fail-open**；② 限流配置**写了但没接线**（`PathLimiter` 是死代码）；③ 所有配置和规则是**进程内存态**，重启即丢。
- 加上一个**已经泄露在 git 里的生产数据库口令**。

---

## 1. 项目现状盘点

| 维度 | 现状 | 评价 |
|---|---|---|
| 数据面 | `httputil.ReverseProxy` + 规则引擎，path/query/header/body 抽取，多重解码 normalize | 架构合理 |
| 规则热更新 | `atomic.Pointer[[]Rule]` + SIGHUP，编译失败保留旧规则 | 好 |
| 限流 | 32 分片 per-IP 令牌桶；`Limiter` + `AutoBanner` | **半成品**，见第 3 节 |
| 管理 API | REST + 可选 Bearer Token + 100rps 硬编码限流 | **默认 fail-open** |
| SSH 堡垒机 | 密码/公钥认证、录像、命令审计、资产 RBAC | 能跑，**缺认证边界与主机密钥校验** |
| 持久化 | 仅堡垒机用户（`users1`）落 MySQL | **配置/规则/资产全在内存** |
| 可观测 | JSON 日志 + 手写 Prometheus 文本 + 健康检查 | **无标签、无延迟、无告警** |
| 部署 | 单静态二进制 | **无 TLS、无集群、无配置版本化** |

---

## 2. 达到生产级还需要实现的功能

### 2.1 阻塞级（P0，不修不能上线）

| # | 问题 | 位置 | 说明 | 修复方向 |
|---|---|---|---|---|
| 1 | 独立堡垒机 API **零认证** | `cmd/bastion/main.go:169-197` | `apiMux` 只包了 `middleware.Logging`，无 token、无 RBAC，默认监听 `:8081` 全网卡。改用户、提权、改配置、下载录像匿名可达 | 复用 `APIServer.authToken`，无 token 拒绝启动；默认监听改 `127.0.0.1` |
| 2 | WAF 内嵌模式 **fail-open** | `api.go:127-129` + `config.yaml:120-124` | `enabled: true` 但 `token: ""` 时 `apiToken==""` → 认证中间件根本不挂载，静默无认证 | `enabled=true && token==""` 时启动即 fatal |
| 3 | 管理 API **无 RBAC** | `bastion/admin_api.go` 全文 | 所有 handler 不校验调用者角色，任何能触达 API 的人可把自己改成 `admin` | 认证上下文 + role claim，写操作强制 `RoleAdmin` |
| 4 | **明文生产口令进了 git** | `config.yaml:96` | `hobart:123456@tcp(78.154.103.23:9257)`，文件 0644 且被跟踪 | 立即轮换口令、`git filter-repo` 清历史、改环境变量注入、文件 0600 + 进 `.gitignore` |
| 5 | 后端主机密钥不校验 | `bastion/proxy.go:62` | `ssh.InsecureIgnoreHostKey()`，MITM 可截获全部后端凭据 | `Asset` 增 `HostKeyFingerprint`，用 `ssh.FixedHostKey` |
| 6 | SSH 登录**无暴力破解防护** | `bastion/server.go:438-446` | 无失败计数、无限速、无锁定，可无限重连爆破 | 复用限流器：per-IP+username 失败计数 + 指数退避 |
| 7 | **默认口令** | `cmd/bastion/main.go:67-68` | `admin/ChangeMe!2024`，配合 #6 等于直接接管 | 首启随机口令或拒绝默认值启动 |
| 8 | 录像**路径穿越** | `bastion/recording.go:72` | `sanitizeUsername`（`recording.go:285`）定义了但从未调用，用户名可含 `../` | 落盘前 `sanitizeUsername` + `filepath.Clean` 前缀校验 |
| 9 | **"禁用命令"不拦截** | `server.go:1119-1177` vs `:893` | 命中只打印提示，命令仍原样发往后端 | 真正劫持输入流并阻断，或文档明确降级为"仅审计" |
| 10 | `HasUser` 吞错 → **创建覆盖已有用户** | `bastion/server.go:312-317` | DB 抖动时误判"用户不存在"，`UpsertUser` 走更新分支覆盖密码/角色 | 改 `(bool, error)`，DB 错误返回 5xx |
| 11 | 配置/规则**重启即丢** | `api.go:252,338,361,471` | PUT `/api/config`、POST `/api/rules` 只改内存，重启回滚且**无审计** | 落库/落文件 + 版本号 + 变更审计 |
| 12 | **无 TLS** | `main.go` | 全项目无 `ListenAndServeTLS`；Bearer Token 明文过网 | 内置 TLS 或强制文档要求前置 LB 终止并禁直连 |

### 2.2 重要级（P1，生产前必须补齐）

| # | 问题 | 位置 | 修复方向 |
|---|---|---|---|
| 13 | `Access-Control-Allow-Origin: *` 覆盖全部管理端点，允许 `Authorization` + 写方法 | `bastion/admin_api.go:857-861` | CORS 白名单化；写操作要求自定义头/CSRF token |
| 14 | `config.security.cors` 配置项**从未接线** | `config/config.go:137-143` | 在 API server 挂 CORS 中间件 |
| 15 | `SessionIdleTimeout` **从未被读取** | `bastion/config.go:37` | I/O 代理加空闲计时器，超时 kill |
| 16 | `MaxSessions` 统计的是**全局连接数**而非每用户 | `server.go:548-557` | 改 `map[username]int` |
| 17 | 空 `Assets` = 可访问**全部**资产；`auditor` 也能登资产 | `server.go:125-131` | 空=无权限（deny by default），角色与资产解耦 |
| 18 | 数据库**无连接池上限** | `internal/store/mysql.go:118-132` | `SetMaxOpenConns(25)/SetMaxIdleConns(10)/SetConnMaxLifetime(30m)` |
| 19 | 录像/审计**无轮转、无保留期**，`RecordingIndex` 无界增长 | `recording.go:209-229`、`audit.go` | 按天/容量滚动清理 + 索引上限 |
| 20 | 审计写失败被吞、无 fsync、无防篡改 | `audit.go:68` | 记录并告警写失败；append-only / 外部收集 |
| 21 | 审计重复写（同步 `Log` + `emitEvent` 各一条） | `server.go:1161-1175`、`:993-1005` | 收敛为单一写入路径 |
| 22 | 分页 `offset+limit` 整数溢出可致 panic（单请求 DoS） | `admin_api.go:683-698` | `limit` 上限 1000，安全边界计算 |
| 23 | `AssetStore` 读-改-写非原子，并发丢更新 | `bastion/assets.go:66-117` | 加互斥或 CAS 重试 |
| 24 | 录像元数据数据竞争（锁内写、锁外读） | `recording.go:155-156` vs `admin_api.go:557-563` | 读也加锁 / 原子字段 |
| 25 | `Asset` 密码/私钥明文存内存，`AssetStore` **无持久化** | `bastion/assets.go:18-43` | KMS/Vault 或加密落库 |
| 26 | `UpsertUser` 非原子（SELECT 后 INSERT/UPDATE） | `user_repository.go:54-72` | `INSERT ... ON DUPLICATE KEY UPDATE` |
| 27 | DB 错误原文回显给客户端 | `admin_api.go:98` 等 | 对外通用错误，细节只进日志 |
| 28 | `commandScanner.buf` 无上限（无换行大粘贴 → 内存增长） | `server.go:1106-1118` | 设最大行长并截断 |
| 29 | `users1` / `user1` 语义混淆，`users1` 建的用户能登 SSH、`user1` 的不能 | `server.go:143-156` | 废弃 `user1` 端点/表，统一到 `users1` |

### 2.3 数据面能力的缺口（WAF 本身）

| # | 缺失 | 说明 |
|---|---|---|
| 30 | **无响应体检测** | 只查入站，数据外泄/被篡改无感知 |
| 31 | **无 multipart 解析** | `multipart/form-data` 整体当文本，文件上传天然绕过 |
| 32 | **无语义检测/评分** | 纯正则，无 libinjection、无 CRS 异常评分，误报漏报靠调参 |
| 33 | 规则集仅 16 条 | 无 OWASP CRS，覆盖度不足 |
| 34 | **无 bot/CC/设备指纹** | 只有 UA 黑名单，现代爬虫绕不过 |
| 35 | **无 IP 信誉库** | 仅静态 allow/deny 列表 |
| 36 | 无 WebSocket / HTTP/2 / gRPC 支持 | 长连接业务无法保护 |
| 37 | 无请求走私防御 | TE/CL 冲突未校验 |
| 38 | 无 URL 规范化一致性（`//`、`;`、大小写路径） | 可被路径混淆绕过规则 |

### 2.4 可观测性 / 运维（P1–P2）

- 指标是**手写字符串拼接**的假 Prometheus：`waf.go:515-554` 无 `Content-Length` 无所谓，但**没有任何标签维度**（无 `rule_id`、`status`、`path`、`upstream`），无法定位问题；应改用 `prometheus/client_golang` 的 `CounterVec/HistogramVec`。
- **无请求延迟直方图**、无上游耗时、无 4xx/5xx 分类计数。
- `/__waf/metrics` 仅本机可访问（`waf.go:492`）——单机部署时 Prometheus 在别的机器上就抓不到；需要 mTLS/内网监听方案而不是硬编码 loopback。
- `/api/healthz` 探活的 `checkUpstream` **每次请求新建 `http.DefaultClient` 连接**（`api.go:784`），高频探测下端口耗尽。
- 无 OpenTelemetry / 链路追踪；无告警规则；日志无采样，高 QPS 下 JSON 日志会成瓶颈。
- 无优雅重启（只有 `Shutdown`，升级仍有连接中断窗口）；无配置版本化/回滚。

### 2.5 多个实例部署

当前所有状态（限流桶、封禁、规则、IP 列表、堡垒机会话/资产）都是**进程内存**。多副本部署会导致：

- 限流 ×N（每副本独立计数）；
- 封禁不共享（A 副本禁了，B 副本照样放行）；
- 规则热更新只作用于单副本；
- 堡垒机会话无法跨副本恢复。

生产需要引入 Redis（限流/封禁/配置广播）或改造为无状态 + 集中配置中心。

---

## 3. 重点：API 限流的具体场景

### 3.1 先看现状（代码事实）

| 事实 | 证据 |
|---|---|
| 数据面只有 **per-IP 单维度**限流 | `waf.go:444-451` 直接用 `w.limiter.Allow(ip)` |
| `PathLimiter`（路径/白名单/全局组合）**从未被实例化** | 全仓库仅 `ratelimit.go` 内部定义，无任何 `NewPathLimiter(` 调用 |
| `config.yaml` 的 `path_rules` / `path_whitelist` / `strategy` **全部空转** | `resolvedConfig` 无对应字段，`buildWAFConfig` 未读取 `RateLimit.PathRules` |
| `rate_limit.enabled` **从未被读取** | 仅 `config.go:35` 定义；`grep RateLimit.Enabled` 无消费点 |
| **热更新 RPS 无效** | `waf.go:112-114` 只在 `w.limiter == nil` 时按新配置建桶，已存在时**不更新 `rate/burst`** |
| 管理 API 限流**硬编码** 100/200 | `main.go:459` `SetAPIRateLimit(100, 200)` |
| 管理 API **认证在限流外层** → 认证失败**不消耗令牌、不限速** | `api.go:125-129`：`authToken` 最后包装，是最外层 |
| `apiLimiter` **没有 GC** | `waf.go:224-228` 只对 `w.limiter` 调 `GC`，`s.apiLimiter` 无任何清理 → 多 IP 访问下 map 无界增长（内存泄漏） |
| 无并发限制、无全局限流、无按 token 配额、无分布式 | — |

> 也就是说：**README 和 config.yaml 里宣传的路径级限流目前是一份"设计稿"**。这本身就是 P0 级别的"配置欺骗"——运维以为 `/login` 限了 10rps，实际完全没有。

### 3.2 限流场景清单（按防护目标组织）

#### 场景 A：管理 API Token 暴力破解防护 —— *认证前限速*

- **触发条件**：`/api/**` 携带错误/缺失 Bearer Token 的请求。
- **现状漏洞**：`authToken` 是最外层中间件（`api.go:127-129`），非法 Token 在 `api.go:157/163/167` 直接返回，**从未进入限流器**。攻击者可无限速猜 Token。
- **设计要求**：
  - 把限流中间件放到**认证外层**（调整包装顺序即可）；
  - 按「源 IP」限速：未认证请求 10 次/分钟；
  - 失败计数按 `IP` 维度累计，5 次/分钟 → 临时封禁 15 分钟（直接复用 `AutoBanner`，`ratelimit.go:117-191`）；
  - 命中返回 `429`，日志打 `warn`，指标自增。
- **关键点**：**不能**因为"Token 是随机的"就省掉这一层——日志噪声和连接资源同样会被打满。

#### 场景 B：探活与监控抓取不能"误伤"，但也不能无限豁免

- **触发条件**：LB 每 3s 探 `/api/healthz`（20 rpm）、Prometheus 每 15s 抓 `/api/metrics`（4 rpm）、`/__waf/metrics`。
- **现状问题**：`authToken` 豁免了 `healthz`（`api.go:150-153`），但**限流没有豁免** → LB 高频探活可能吃 429，进而被摘除节点；反之若简单把健康检查加进全局白名单，又给了攻击者一个不限速路径。
- **设计要求**：
  - 分档而非豁免：`healthz` 给 **独立的宽松桶**（如 50 rps），不进全局池；
  - 白名单必须**绑定源网段**（只允许 LB/Prometheus 所在 CIDR），不能只按路径；
  - 监控抓取按 **Token/来源** 识别，而非路径。

#### 场景 C：读操作与写操作分级限流

- **触发条件**：`GET /api/rules|metrics|config` vs `PUT /api/config`、`POST /api/rules`、`POST/DELETE /api/allow|deny`、`/api/bastion/**` 写操作。
- **为什么必须分**：写操作会**改变防护状态**。前端一次误点、一段死循环脚本或一次前端 hot-reload 风暴，就可能反复覆盖规则/配置。读操作再频繁也只是浪费 CPU。
- **设计要求（建议阈值）**：

  | 接口类别 | 示例 | 限额 | 超限响应 |
  |---|---|---|---|
  | 读/查询 | `GET /api/metrics`、`GET /api/rules` | 100 rps / burst 200 | `429` |
  | 写/变更 | `PUT /api/config`、`POST /api/rules`、IP 增删 | **5 rps / burst 10** | `429` |
  | 堡垒机写 | `POST/PUT/DELETE /api/bastion/users|assets|config` | **2 rps / burst 5** | `429` |
  | 探活 | `GET /api/healthz` | 50 rps，仅限 LB 网段 | `429` |

- **实现要点**：按 `method + 路由前缀` 选择限流桶，而不是一个全局桶。`PathLimiter` 的骨架（`ratelimit.go:242`）可以直接复用，但**匹配逻辑需要修**——见 3.4。

#### 场景 D：重资源接口的**并发**闸门（不是 QPS）

- **触发条件**：`GET /api/bastion/sessions/{id}/recording`（下载整段录像，可能数十 MB）、`GET /api/bastion/audit?limit=`（当前 `limit` 无上限，见 2.2#22）、`GET /api/bastion/sessions`。
- **为什么 QPS 不够**：1 rps 的录像下载如果每个都持续 60s，并发就是 60，带宽/内存先炸。
- **设计要求**：对这类接口用**信号量限并发**（每 IP 2 个、全局 10 个），持满返回 `429` + `Retry-After`。同时给 `limit` 加上限。

#### 场景 E：按调用方的配额（token / user 维度）

- **触发条件**：同一套管理 API 被监控系统、CI/CD、运维平台、前端共用。
- **现状**：`config.yaml` 声明 `strategy: per_user`，但**代码里没有任何 per-user 限流实现**。
- **设计要求**：以 Token（或 Token 的 hash）为 key 建独立桶，各方互不影响；给监控/CI 单独的只读 Token 与配额。这样才能做到"CI 狂刷不影响运维改配置"。

#### 场景 F：单 IP 限流挡不住分布式 → 需要全局总闸

- **触发条件**：僵尸网络/多出口代理用成千上万个 IP 打管理口；或 WAF 数据面被大规模 CC。
- **设计要求**：
  - **全局 QPS 上限**（如 2000 rps）+ **全局并发上限**，与前端的 per-IP 桶**同时生效**（先查 per-IP，再查全局）；
  - 全局超限返回 **`503 Service Unavailable`**（表示整体过载），per-IP 超限返回 **`429`**（表示"你自己太快"）——两者语义不同，便于告警区分；
  - 全局桶必须**多副本可协调**（见场景 G）。

#### 场景 G：多副本部署下的一致性

- **问题**：令牌桶在进程内，3 副本 → 实际限额 ×3；封禁不共享。
- **设计要求（二选一）**：
  1. **集中式**：Redis + Lua 做原子令牌桶（推荐，行为精确）；
  2. **分摊式**：配置限额 ÷ 副本数下发（实现简单，但副本动态伸缩时不准，可作为过渡）。

#### 场景 H：限流器自身的资源管理

- **问题**：`s.apiLimiter` 无 GC（`waf.go:224` 只清理数据面限流器），任何能访问 `:8081` 的多 IP 来源都会让 `map[netip.Addr]*bucket` 无界增长。
- **设计要求**：把 GC 抽成统一后台任务，同时清理数据面与 API 限流器；或统一由一个 `RateLimiterRegistry` 管理所有桶与生命周期。

#### 场景 I：返回语义与可观测

- **响应头**（IETF `RateLimit` 草案）：`Retry-After`、`RateLimit-Limit`、`RateLimit-Remaining`、`RateLimit-Reset`。
- **现状**：只有 `Retry-After`，且 `api.go:78` 用 `%.0f`（<1s 时返回 `0`，语义错误）、数据面 `waf.go:447` 用 `math.Ceil`（最小 1）。
- **指标**：`gowaf_rate_limited_total{scope="api|waf", key_type="ip|token", route="/api/config"}`，无标签的计数在生产里没法定位。
- **日志**：记录 key、限额、当前速率、路由；并对反复超限的 IP 触发 `AutoBanner` 自动封禁。

#### 场景 J：SSH 登录限速（复用同一套限流设施）

- **触发条件**：`bastion/server.go:438-446` 当前无任何防护。
- **设计要求**：key = `源IP` 与 `username` 双维度（防"换用户名绕 IP 限制"和"换 IP 打同一账号"）；5 次失败 / 5 分钟 → 退避 + 告警；账号维度连续失败 → 锁定并需要管理员解锁。

### 3.3 推荐的落地配置（目标形态）

```yaml
rate_limit:
  enabled: true                # 必须真正生效
  default:                     # 数据面默认 per-IP
    rps: 20.0
    burst: 40
  global:                      # 全局兜底（场景 F）
    rps: 2000.0
    burst: 4000
    overload_status: 503
  path_whitelist:              # 需要绑定来源网段，不能只按路径
    - path: "/api/healthz"
      cidrs: ["10.0.0.0/8"]
      rps: 50.0
    - path: "/__waf/metrics"
      cidrs: ["10.0.0.0/8"]
  path_rules:                  # 场景 C：分级
    - path: "/login"
      rps: 5.0
      burst: 10
    - path: "/api/*"
      method: GET
      rps: 100.0
      burst: 200
    - path: "/api/*"
      method: POST|PUT|DELETE
      rps: 5.0
      burst: 10
  concurrency:                 # 场景 D：重资源接口
    - path: "/api/bastion/sessions/*/recording"
      per_ip: 2
      global: 10
  api_auth:
    unauthenticated_rps: 0.16  # ≈10 次/分钟（场景 A）
    lockout_strikes: 5
    lockout_window: "1m"
    lockout_duration: "15m"
  ssh_login:                   # 场景 J
    strikes: 5
    window: "5m"
    backoff: "exponential"
  distributed:                 # 场景 G
    backend: "memory"          # memory | redis
    redis_addr: ""
  auto_ban:
    enabled: true
    strikes: 5
    window: "1m"
    duration: "10m"
```

### 3.4 现有实现的代码级缺陷清单（修限流必看）

| # | 缺陷 | 位置 | 影响 | 修法 |
|---|---|---|---|---|
| L1 | `PathLimiter` 死代码 | `ratelimit.go:37-335` | 路径限流/白名单/全局组合全部不生效 | 在 `New()` 里按配置构造并接入 `Handler` |
| L2 | RPS/Burst 热更新无效 | `waf.go:112-114` | PUT `/api/config` 改 RPS 无任何效果 | `SetConfig` 中重建或原子更新 `rate/burst` |
| L3 | `rate_limit.enabled` 未读 | `config/config.go:35` | 配 `false` 也照样限流 | `buildWAFConfig` 消费该字段 |
| L4 | API 认证在限流外层 | `api.go:125-129` | Token 爆破不限速（场景 A） | 交换包装顺序 |
| L5 | `apiLimiter` 无 GC | `waf.go:224-228` | 内存无界增长（场景 H） | 统一 GC 所有限流器 |
| L6 | API 限流硬编码 | `main.go:459` | 无法配置/调优 | 从 YAML 读取 |
| L7 | `AllowWithGlobal` 逻辑缺陷 | `ratelimit.go:274-298` | 路径桶已扣令牌、全局桶再拒绝时**令牌泄漏**；且未匹配任何 path 规则时**只**查全局、丢弃 per-IP 语义 | 先判定再统一扣减，或两阶段 commit |
| L8 | 路径匹配用 `strings.HasPrefix` | `ratelimit.go:232,258` | `/api*` 会误匹配 `/apixxx`；`*` 只支持后缀一种形式 | 规范化通配符匹配（段级匹配） |
| L9 | `NewLimiter(0, ...)` 可产生 NaN | `ratelimit.go:52-58,97` | `rate=0` 时 `wait` 计算除零 | 构造时校验 `rps>0` |
| L10 | `Retry-After` 为 0 | `api.go:78` | `<1s` 时返回 `0`，客户端可立即重试 | 向上取整且最小 1 |
| L11 | 无 `RateLimit-*` 头 | `api.go:77-80`、`waf.go:447` | 客户端无法自适应 | 补齐标准头 |
| L12 | 限流无指标/无审计 | 全局 | 生产无法定位 | 加带标签的 Counter + 日志 |
| L13 | 数据面 `n` 个限流器但 `PathLimiter.GC` 未调用 | `ratelimit.go:301-306` | 若接入 `PathLimiter` 后忘记 GC，同样泄漏 | 统一 GC 入口 |

---

## 4. 建议实施顺序

**第 1 批（安全边界，1–2 天）**
1. 两种部署模式统一认证 + 启动期 fail-closed（P0#1、#2）
2. 轮换并移除 git 中的 DSN，`config.yaml` 改 0600 + 环境变量（P0#4）
3. 管理 API 认证前限速 + 失败锁定（场景 A）
4. 修 `sanitizeUsername` 路径穿越（P0#8）
5. `HasUser` 错误语义修正（P0#10）

**第 2 批（限流接线，2–3 天）**
6. 在 `New()` 中构造 `PathLimiter` 并接入 `Handler`，实现场景 C/D/E
7. 修 L1–L13，补 `RateLimit-*` 头与指标
8. API 限流配置化 + 统一 GC（场景 H）
9. SSH 登录限速（场景 J）

**第 3 批（可靠性与可观测，3–5 天）**
10. 配置/规则持久化 + 变更审计（P0#11）
11. 录像/审计轮转与保留期（P1#19、#20）
12. 连接池上限、并发缺陷、整数溢出（P1#18、#22、#23、#24）
13. 换成真正的 Prometheus 客户端 + 延迟直方图（2.4）
14. TLS 终止与内网监听策略（P0#12）

**第 4 批（架构演进，按需）**
15. Redis 集中限流/封禁/配置广播（场景 G、2.5）
16. 后端主机密钥校验、RBAC 角色模型（P0#3、#5）
17. 响应体检测、multipart、语义检测/CRS（2.3）

---

## 附：本次分析使用的验证方法

- 逐文件阅读 `main.go`、`waf.go`、`ratelimit.go`、`api.go`、`rules.go`、`config/config.go`、`bastion/*`、`cmd/bastion/main.go`、`internal/store/*`、`models/*`。
- 用 `grep` 交叉验证"配置项是否有消费点"（`PathLimiter`、`RateLimit.Enabled`、`SessionIdleTimeout`、`CORS`、`SetMaxOpenConns` 均无消费点）。
- 实测 `go vet ./...`、`go build ./...`、`go test -race ./...`（使用本机默认 module cache，`GOPROXY=off`）。
- 堡垒机模块由独立审计子任务并行核查，结论已并入第 2 节。
