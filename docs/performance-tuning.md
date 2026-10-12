# GoWAF 性能调优指南

## 目录

- [性能基准](#性能基准)
- [限流调优](#限流调优)
- [连接池配置](#连接池配置)
- [Go 运行时调优](#go-运行时调优)
- [内核参数调优](#内核参数调优)
- [监控与瓶颈分析](#监控与瓶颈分析)

---

## 性能基准

### 硬件信息

测试环境: 2 vCPU, 4 GB RAM, Linux

### 延迟数据

| 场景 | 平均延迟 | P99 延迟 | QPS |
|------|---------|----------|-----|
| 正常请求 (规则未命中) | 39 µs | 80 µs | ~25,000 |
| 攻击请求 (规则命中) | 3.4 µs | 10 µs | ~294,000 |
| 限流触发 | 5 µs | 15 µs | ~200,000 |

### 性能影响因素

1. **规则数量**: 规则越多，干净流量越慢
2. **正则复杂度**: 复杂正则会增加 CPU 消耗
3. **请求体大小**: 大 body 会增加处理时间
4. **限流分片**: 32 分片在高并发下性能良好

---

## 限流调优

### 基础限流参数

```yaml
rate_limit:
  enabled: true
  rps: 50        # 每 IP 每秒请求数
  burst: 100     # 突发容量 (建议 = rps * 2)
  strategy: "per_ip"
```

### 限流策略选择

| 策略 | 适用场景 | 配置示例 |
|------|---------|---------|
| `per_ip` | 通用场景，防止单个 IP 刷接口 | rps: 50, burst: 100 |
| `per_path` | API 差异化限流，敏感接口更严格 | 见下方配置 |
| `per_user` | 已认证用户，需配合 API 认证 | rps: 100, burst: 200 |

### 按路径差异化限流

```yaml
rate_limit:
  enabled: true
  strategy: "per_path"
  
  # 限流例外路径
  path_whitelist:
    - "/api/healthz"
    - "/api/metrics"
    - "/__waf/metrics"
  
  # 按路径限流规则
  path_rules:
    - path: "/api/*"
      rps: 30.0
      burst: 60
    
    - path: "/login"
      rps: 10.0      # 登录接口更严格
      burst: 20
    
    - path: "/api/search"
      rps: 20.0
      burst: 40
    
    - path: "/static/*"
      rps: 100.0     # 静态资源可以更宽松
      burst: 200
```

### 限流计算公式

```
令牌补充速度 = rps (每秒补充 rps 个令牌)
突发容量 = burst (最大可持有令牌数)
建议 burst = rps * 2

请求等待时间 = (1 - 当前令牌数) / rps
```

### 自动封禁调优

```yaml
rate_limit:
  auto_ban:
    enabled: true
    strikes: 5        # 窗口内违规次数
    window: "1m"     # 时间窗口
    duration: "10m"   # 封禁时长
```

**调整建议:**
- 高流量 API: `strikes: 10, window: 30s`
- 敏感接口: `strikes: 3, duration: 30m`

---

## 连接池配置

### 上游连接池

```yaml
upstream:
  url: "http://127.0.0.1:9000"
  dial_timeout: 3          # TCP 连接超时 (秒)
  idle_timeout: 90         # 空闲连接超时 (秒)
  max_idle_conns: 100      # 最大空闲连接数
```

### 连接池调优公式

```
max_idle_conns = 上游服务器数量 * 每个服务器的预期并发请求数

例如:
- 2台上游服务器
- 每台预期 50 并发请求
- max_idle_conns = 2 * 50 = 100
```

### HTTP/2 建议

如果上游支持 HTTP/2:

```yaml
upstream:
  # 使用 HTTP/2 可以提高连接复用
  url: "http://127.0.0.1:9000"
  http2: true
```

---

## Go 运行时调优

### GOMAXPROCS

```bash
# 方案一: 环境变量
export GOMAXPROCS=4

# 方案二: 在启动脚本中设置
./gowaf -gomaxprocs 4

# 方案三: 自动检测 (推荐)
# Go 1.19+ 自动适配
```

### GOGC (垃圾回收)

```bash
# 减少 GC 频率 (以内存换性能)
export GOGC=200  # 默认 100，设为 200 表示内存增长到 2 倍时才 GC

# 高并发场景建议
export GOGC=150
```

### 内存限制

```bash
# 限制最大内存
export GOMEMLIMIT=1073741824  # 1GB
```

### 推荐的生产环境变量

```bash
export GOMAXPROCS=4
export GOGC=150
export GOMEMLIMIT=1073741824  # 1GB 内存限制
```

---

## 内核参数调优

### sysctl.conf 建议

```bash
# /etc/sysctl.conf

# 网络连接优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# TIME_WAIT 优化
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# 连接跟踪 (如果使用 iptables)
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# 文件描述符
fs.file-max = 2097152
```

### 应用限制

```bash
# /etc/security/limits.conf
gowaf soft nofile 65536
gowaf hard nofile 65536
gowaf soft nproc 4096
gowaf hard nproc 4096
```

### 应用 systemd 配置

```ini
[Service]
LimitNOFILE=65536
LimitNPROC=4096
```

---

## 监控与瓶颈分析

### 关键指标

通过 `/__waf/metrics` 端点监控:

```bash
curl http://localhost:8080/__waf/metrics
```

```json
{
  "requests_total": 1234567,
  "rule_matched": 1234,
  "blocked": 567,
  "rate_limited": 89,
  "rules_loaded": 16,
  "mode": "block"
}
```

### 告警阈值建议

| 指标 | 警告 | 严重 | 说明 |
|------|------|------|------|
| blocked_rate | > 5% | > 10% | 可能遭受攻击 |
| rate_limited_rate | > 2% | > 5% | 限流触发频繁 |
| latency_p99 | > 100ms | > 500ms | 性能下降 |
| error_rate | > 0.1% | > 1% | 服务异常 |

### 性能分析工具

```bash
# 1. pprof HTTP 端点 (添加 -pprof 参数)
./gowaf -pprof :6060

# 2. CPU profile
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof

# 3. 内存 profile
curl http://localhost:6060/debug/pprof/heap > mem.prof

# 4. 分析
go tool pprof -http=:8080 cpu.prof
```

### 瓶颈排查流程

1. **CPU 高**: 检查规则复杂度，考虑添加关键词预过滤
2. **内存高**: 检查限流器 GC，调整 `GOGC`
3. **延迟高**: 检查上游响应时间，优化连接池
4. **限流频繁**: 调整 rps/burst 参数

---

## 推荐配置

### 小型部署 (1核 512MB)

```yaml
waf:
  mode: "block"
  max_body: 524288  # 512KB

rate_limit:
  enabled: true
  rps: 20
  burst: 40
  strategy: "per_ip"

server:
  listen: ":8080"
  read_header_timeout: "5s"
  read_timeout: "10s"
  write_timeout: "30s"

upstream:
  url: "http://127.0.0.1:9000"
  max_idle_conns: 50
```

### 中型部署 (2核 2GB)

```yaml
waf:
  mode: "block"
  max_body: 1048576  # 1MB

rate_limit:
  enabled: true
  rps: 50
  burst: 100
  strategy: "per_ip"

server:
  listen: ":8080"
  read_header_timeout: "5s"
  read_timeout: "15s"
  write_timeout: "60s"

upstream:
  url: "http://127.0.0.1:9000"
  max_idle_conns: 100
```

### 大型部署 (4核+ 4GB+)

```yaml
waf:
  mode: "block"
  max_body: 1048576

rate_limit:
  enabled: true
  rps: 100
  burst: 200
  strategy: "per_path"
  path_whitelist:
    - "/api/healthz"
    - "/api/metrics"
  path_rules:
    - path: "/api/*"
      rps: 50
      burst: 100
    - path: "/static/*"
      rps: 200
      burst: 400

server:
  listen: ":8080"
  read_header_timeout: "5s"
  read_timeout: "15s"
  write_timeout: "60s"
  idle_timeout: "60s"

upstream:
  url: "http://127.0.0.1:9000"
  max_idle_conns: 200
```

---

## 相关文档

- [部署指南](./deployment-guide.md)
- [安全加固](./security-hardening.md)
- [监控与可观测性](./monitoring.md)