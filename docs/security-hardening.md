# GoWAF 安全加固指南

## 目录

- [网络安全](#网络安全)
- [访问控制](#访问控制)
- [数据安全](#数据安全)
- [SSH 堡垒机安全](#ssh-堡垒机安全)
- [日志与审计](#日志与审计)
- [安全建议清单](#安全建议清单)

---

## 网络安全

### 1. 网络隔离

```
                            ┌─────────────┐
                            │   客户端    │
                            └──────┬──────┘
                                   │
                            ┌──────▼──────┐
                            │     WAF     │  ← 只暴露必要端口
                            │  (GoWAF)    │
                            └──────┬──────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
             ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
             │   源站 1    │ │   源站 2    │ │   MySQL     │
             └─────────────┘ └─────────────┘ └─────────────┘
```

**防火墙规则示例 (iptables):**

```bash
# 允许的入站规则
-A INPUT -p tcp --dport 8080 -j ACCEPT    # WAF 监听端口
-A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT  # API 限制内网访问
-A INPUT -p tcp --dport 2222 -s 10.0.0.0/8 -j ACCEPT  # SSH 堡垒机限制内网访问

# 默认拒绝
-A INPUT -j DROP
```

### 2. TLS 配置

虽然 GoWAF 本身不处理 TLS，但建议通过反向代理实现：

```nginx
# 使用强 TLS 配置
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_tickets off;

# HSTS (启用后浏览器强制 HTTPS)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 3. 隐藏版本信息

在 `config.yaml` 中启用:

```yaml
security:
  hide_version: true
```

---

## 访问控制

### 1. IP 白名单

```yaml
ip:
  # 只允许内网和特定 IP 访问
  allow:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "203.0.113.0/24"  # 示例: 第三方监控 IP
  deny:
    - "0.0.0.0/0"       # 拒绝所有 (先拒绝后允许)
```

### 2. API 认证 (未来扩展)

```yaml
security:
  api_auth:
    enabled: true
    type: "token"  # basic / token
```

### 3. 敏感端点保护

通过反向代理限制管理接口访问:

```nginx
location /api/ {
    # 只允许内网访问管理 API
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    deny all;
    
    proxy_pass http://gowaf_backend;
}
```

---

## 数据安全

### 1. 数据库连接安全

```yaml
database:
  # 使用 TLS 连接 (如果 MySQL 支持)
  mysql_dsn: "user:pass@tcp(mysql.example.com:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local&tls=true"
```

### 2. 密码安全

- **初始管理员密码必须修改**

```bash
# 不要使用默认密码
./gowaf -ssh-admin-user admin -ssh-admin-pass "YourSecurePassword!@#$%^&*()"
```

- **使用强密码策略**

```bash
# 生成随机密码
openssl rand -base64 32
```

### 3. 会话录像加密 (未来扩展)

```yaml
bastion:
  # 录像加密 (待实现)
  recording_encryption: true
  recording_key: "${RECORDING_KEY}"  # 从环境变量读取
```

---

## SSH 堡垒机安全

### 1. SSH 密钥管理

```bash
# 生成 SSH 密钥对 (Ed25519, 推荐)
ssh-keygen -t ed25519 -f ~/.ssh/gowaf_bastion

# 禁用密码登录 (在 sshd_config 中)
PasswordAuthentication no
PubkeyAuthentication yes
```

### 2. 禁止命令配置

GoWAF 内置危险命令禁止列表:

```go
var defaultBannedCommands = []bastion.BannedCommand{
    {ID: "ban-001", Pattern: "rm -rf /", Reason: "destructive command", Enabled: true},
    {ID: "ban-002", Pattern: "mkfs", Reason: "filesystem format", Enabled: true},
    {ID: "ban-003", Pattern: "dd if=/dev/zero", Reason: "disk overwrite", Enabled: true},
    {ID: "ban-004", Pattern: ":(){:|:&};:", Reason: "fork bomb", Enabled: true},
    {ID: "ban-005", Pattern: "chmod 777 /", Reason: "dangerous permission change", Enabled: true},
    {ID: "ban-006", Pattern: "shutdown", Reason: "system shutdown", Enabled: true},
    {ID: "ban-007", Pattern: "reboot", Reason: "system reboot", Enabled: true},
    {ID: "ban-008", Pattern: "init 0", Reason: "system halt", Enabled: true},
}
```

### 3. 会话超时

```yaml
bastion:
  session_idle_timeout: "10m"  # 10 分钟空闲断开
  max_sessions: 50             # 限制并发会话
```

### 4. IP 访问限制

```bash
# 使用 TCP Wrappers 限制 SSH 访问
echo "sshd: 10.0.0.0/8" >> /etc/hosts.allow
echo "sshd: ALL" >> /etc/hosts.deny
```

---

## 日志与审计

### 1. 日志配置

```yaml
logging:
  level: "info"        # 生产环境用 info,调试用 debug
  format: "json"        # 结构化日志便于分析
  output: "file"        # 生产环境写入文件
  file_path: "/var/log/gowaf/app.log"
```

### 2. 日志轮转 (logrotate)

```bash
# /etc/logrotate.d/gowaf
/var/log/gowaf/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 gowaf gowaf
    postrotate
        kill -HUP $(pidof gowaf) 2>/dev/null || true
    endscript
}
```

### 3. 审计日志

```bash
# 审计日志文件权限
chmod 600 /var/log/gowaf/audit.log

# 审计日志保留 (建议 1 年)
# 定期归档到冷存储
```

### 4. 集中日志收集

```json
{
  "journald": {
    "enabled": true,
    "syslog_identifier": "gowaf"
  },
  "fluentd": {
    "enabled": true,
    "host": "log-collector.example.com",
    "port": 24224
  }
}
```

---

## 安全建议清单

### 部署前检查

- [ ] 修改默认管理员密码
- [ ] 限制 API 端口仅内网访问
- [ ] 配置防火墙规则
- [ ] 启用 TLS (通过反向代理)
- [ ] 配置日志轮转
- [ ] 设置数据库连接 TLS

### 日常运维

- [ ] 定期审查审计日志
- [ ] 监控异常访问模式
- [ ] 及时更新 Go 版本和依赖
- [ ] 定期备份配置和数据库
- [ ] 测试灾难恢复流程

### 监控告警

建议设置以下告警:

| 告警项 | 阈值 | 说明 |
|--------|------|------|
| 403 响应率 | > 10% | 可能正在遭受攻击 |
| 限流触发次数 | > 100/分钟 | 可能需要调整限流参数 |
| 错误率 | > 1% | 服务可能异常 |
| 延迟 P99 | > 500ms | 性能可能下降 |
| 磁盘使用率 | > 80% | 需要清理录像 |

---

## 相关文档

- [部署指南](./deployment-guide.md)
- [性能调优](./performance-tuning.md)
- [监控与可观测性](./monitoring.md)