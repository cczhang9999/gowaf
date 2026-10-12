# GoWAF 监控与可观测性指南

## 目录

- [指标体系](#指标体系)
- [Prometheus 集成](#prometheus-集成)
- [Grafana 仪表盘](#grafana-仪表盘)
- [日志分析](#日志分析)
- [告警规则](#告警规则)
- [健康检查](#健康检查)

---

## 指标体系

### 内置指标端点

GoWAF 提供两个指标端点:

1. **WAF 指标** (`/:8080/__waf/metrics` 或 `/:8081/api/metrics`)
2. **Prometheus 格式** (需开启 -prometheus 参数)

```bash
# WAF JSON 指标
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

### 指标说明

| 指标 | 类型 | 说明 |
|------|------|------|
| `requests_total` | Counter | 总请求数 |
| `rule_matched` | Counter | 规则匹配次数 |
| `blocked` | Counter | 拦截请求数 |
| `rate_limited` | Counter | 限流触发次数 |
| `allow_count` | Gauge | 白名单 IP 数量 |
| `deny_count` | Gauge | 黑名单 IP 数量 |

---

## Prometheus 集成

### 1. 启用 Prometheus 端点

GoWAF 暂时不内置 Prometheus 端点，需要通过Exporter 转换:

```bash
# 使用 nginx 的指标端点
curl -s http://localhost:8081/api/metrics | jq .
```

### 2. 配置 Prometheus 抓取

```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'gowaf'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/api/metrics'
    scrape_interval: 10s
```

### 3. 自定义 Exporter (可选)

如果需要 Prometheus 格式，可以部署以下 Exporter:

```dockerfile
# Dockerfile.exporter
FROM golang:1.24-alpine
WORKDIR /app
RUN go install github.com/gowaf/prometheus-exporter@latest
ENTRYPOINT ["/go/bin/prometheus-exporter"]
EXPOSE 9100
```

---

## Grafana 仪表盘

### 仪表盘 JSON

创建 `grafana-dashboard.json`:

```json
{
  "annotations": {
    "list": []
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "liveNow": false,
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate(requests_total[5m])",
          "legendFormat": "Requests/sec",
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate(blocked[5m])",
          "legendFormat": "Blocked/sec",
          "refId": "B"
        }
      ],
      "title": "请求速率",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.05
              },
              {
                "color": "red",
                "value": 0.1
              }
            ]
          },
          "unit": "percentunit"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "blocked / requests_total",
          "legendFormat": "Block Rate",
          "refId": "A"
        }
      ],
      "title": "拦截率",
      "type": "gauge"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.02
              },
              {
                "color": "red",
                "value": 0.05
              }
            ]
          },
          "unit": "percentunit"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 18,
        "y": 0
      },
      "id": 3,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate_limited / requests_total",
          "legendFormat": "Rate Limit Rate",
          "refId": "A"
        }
      ],
      "title": "限流率",
      "type": "gauge"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            }
          },
          "mappings": []
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 8
      },
      "id": 4,
      "options": {
        "legend": {
          "displayMode": "list",
          "placement": "right",
          "showLegend": true
        },
        "pieType": "pie",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rule_matched",
          "legendFormat": "Rule Matched",
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "blocked",
          "legendFormat": "Blocked",
          "refId": "B"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate_limited",
          "legendFormat": "Rate Limited",
          "refId": "C"
        }
      ],
      "title": "请求分类",
      "type": "piechart"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 12,
        "y": 8
      },
      "id": 5,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "requests_total",
          "legendFormat": "Total Requests",
          "refId": "A"
        }
      ],
      "title": "总请求数",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 18,
        "y": 8
      },
      "id": 6,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto"
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rules_loaded",
          "legendFormat": "Rules Loaded",
          "refId": "A"
        }
      ],
      "title": "已加载规则数",
      "type": "stat"
    }
  ],
  "refresh": "5s",
  "schemaVersion": 38,
  "style": "dark",
  "tags": ["gowaf", "waf"],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "GoWAF Dashboard",
  "uid": "gowaf-dashboard",
  "version": 1
}
```

### 导入仪表盘

1. 登录 Grafana
2. 点击 "+" → "Import"
3. 上传 `grafana-dashboard.json` 或粘贴 JSON
4. 选择 Prometheus 数据源
5. 点击 "Import"

---

## 日志分析

### 日志格式 (JSON)

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "WARN",
  "msg": "request rejected",
  "id": "a1b2c3d4e5f6",
  "ip": "192.168.1.100",
  "status": 403,
  "reason": "rule_match",
  "method": "GET",
  "path": "/admin/login",
  "rule": "sqli-001",
  "category": "sqli",
  "where": "query"
}
```

### 日志字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 请求唯一 ID |
| `ip` | string | 客户端 IP |
| `status` | int | HTTP 响应码 |
| `reason` | string | 拒绝原因 (rule_match, rate_limited, ip_denied, bad_body) |
| `rule` | string | 匹配的规则 ID |
| `category` | string | 攻击类别 |
| `where` | string | 匹配位置 (path, query, body, header:xxx) |

### 日志分析示例

```bash
# 查看被拦截的请求
grep '"reason":"rule_match"' /var/log/gowaf/app.log | jq .

# 查看 SQL 注入攻击
grep '"category":"sqli"' /var/log/gowaf/app.log | jq '.ip, .path, .rule'

# 查看限流触发
grep '"reason":"rate_limited"' /var/log/gowaf/app.log | jq '.ip, .path'

# 统计每分钟拦截数
grep '"status":403' /var/log/gowaf/app.log | jq '.time[0:16]' | sort | uniq -c

# 查看被封禁的 IP
grep '"msg":"ip banned"' /var/log/gowaf/app.log | jq '.ip, .for'
```

### ELK Stack 集成

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/gowaf/*.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "gowaf-%{+yyyy.MM.dd}"
```

---

## 告警规则

### Prometheus 告警规则

创建 `gowaf-alerts.yml`:

```yaml
groups:
  - name: gowaf_alerts
    rules:
      # 高拦截率告警
      - alert: HighBlockRate
        expr: (blocked / requests_total) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "WAF 拦截率过高"
          description: "拦截率超过 10%，当前值: {{ $value | humanizePercentage }}"

      # 严重攻击告警
      - alert: SevereAttack
        expr: (blocked / requests_total) > 0.3
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF 正在遭受严重攻击"
          description: "拦截率超过 30%，当前值: {{ $value | humanizePercentage }}"

      # 限流触发告警
      - alert: HighRateLimitTriggers
        expr: rate(rate_limited[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "限流触发频繁"
          description: "限流触发速率超过 100/秒"

      # 服务不可用告警
      - alert: WAFDown
        expr: up{job="gowaf"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF 服务不可用"
          description: "WAF 健康检查失败"

      # 规则未加载告警
      - alert: NoRulesLoaded
        expr: rules_loaded == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF 规则未加载"
          description: "WAF 没有任何加载的规则，正在放行所有流量"
```

### 告警路由配置

```yaml
# alertmanager.yml
route:
  group_by: ['alertname']
  receiver: 'email'
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
    - match:
        severity: warning
      receiver: 'email'

receivers:
  - name: 'email'
    email_configs:
      - to: 'ops@example.com'
        send_resolved: true

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_SERVICE_KEY'
        severity: critical
```

---

## 健康检查

### 健康检查端点

```bash
# WAF 健康检查
curl http://localhost:8081/api/healthz
# 返回: OK

# 堡垒机健康检查
curl http://localhost:8081/api/bastion/healthz
# 返回: {"status":"ok","user_store":"mysql(user1)"}
```

### Kubernetes 健康检查配置

```yaml
livenessProbe:
  httpGet:
    path: /api/healthz
    port: 8081
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /api/healthz
    port: 8081
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

---

## 相关文档

- [部署指南](./deployment-guide.md)
- [安全加固](./security-hardening.md)
- [性能调优](./performance-tuning.md)