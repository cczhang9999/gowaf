# GoWAF 生产环境部署指南

## 目录

- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [Docker 部署](#docker-部署)
- [Kubernetes 部署](#kubernetes-部署)
- [systemd 服务](#systemd-服务)
- [反向代理配置](#反向代理配置)
- [配置管理](#配置管理)

---

## 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|---------|---------|
| CPU | 1 核 | 2+ 核 |
| 内存 | 512 MB | 1 GB+ |
| 磁盘 | 1 GB | 5 GB+ (含录像存储) |
| Go 版本 | 1.21+ | 1.24+ |
| 操作系统 | Linux/macOS/Windows | Linux (Ubuntu 22.04+) |

---

## 快速开始

### 1. 下载或编译

```bash
# 方式一: 下载预编译二进制
wget https://github.com/yourrepo/gowaf/releases/latest/download/gowaf-linux-amd64.tar.gz
tar -xzf gowaf-linux-amd64.tar.gz

# 方式二: 自行编译
git clone https://github.com/yourrepo/gowaf.git
cd gowaf
go build -o gowaf .
```

### 2. 基本运行

```bash
# 启动 WAF (保护 http://127.0.0.1:9000)
./gowaf -listen :8080 -upstream http://127.0.0.1:9000

# 访问测试
curl -i 'http://127.0.0.1:8080/?q=1+union+select+1'  # 应返回 403
curl -i 'http://127.0.0.1:8080/?q=hello'              # 正常转发
```

### 3. 使用配置文件

```bash
# 使用 YAML 配置 (推荐)
./gowaf -config config.yaml

# 配置优先于默认值的示例: CLI flags 覆盖配置文件
./gowaf -config config.yaml -listen :9090 -rps 100
```

---

## Docker 部署

### Dockerfile

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o gowaf .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/gowaf /usr/local/bin/
COPY config.yaml.example /etc/gowaf/config.yaml
EXPOSE 8080 8081 2222
ENTRYPOINT ["gowaf", "-config", "/etc/gowaf/config.yaml"]
```

### 构建并运行

```bash
# 构建镜像
docker build -t gowaf:latest .

# 运行容器
docker run -d \
  --name gowaf \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 2222:2222 \
  -v $(pwd)/config.yaml:/etc/gowaf/config.yaml \
  -v $(pwd)/recordings:/recordings \
  -v $(pwd)/audit.log:/audit.log \
  --restart unless-stopped \
  gowaf:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  gowaf:
    image: gowaf:latest
    container_name: gowaf
    ports:
      - "8080:8080"    # WAF 监听端口
      - "8081:8081"    # API 管理端口
      - "2222:2222"    # SSH 堡垒机端口
    volumes:
      - ./config.yaml:/etc/gowaf/config.yaml:ro
      - ./recordings:/recordings
      - ./audit.log:/audit.log
    environment:
      - TZ=Asia/Shanghai
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/api/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

```bash
# 启动
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止
docker-compose down
```

---

## Kubernetes 部署

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gowaf
  namespace: waf
  labels:
    app: gowaf
spec:
  replicas: 2
  selector:
    matchLabels:
      app: gowaf
  template:
    metadata:
      labels:
        app: gowaf
    spec:
      containers:
        - name: gowaf
          image: gowaf:latest
          ports:
            - containerPort: 8080
              name: waf
            - containerPort: 8081
              name: api
            - containerPort: 2222
              name: ssh
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          volumeMounts:
            - name: config
              mountPath: /etc/gowaf
              readOnly: true
            - name: recordings
              mountPath: /recordings
          env:
            - name: TZ
              value: "Asia/Shanghai"
          livenessProbe:
            httpGet:
              path: /api/healthz
              port: 8081
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /api/healthz
              port: 8081
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: gowaf-config
        - name: recordings
          persistentVolumeClaim:
            claimName: gowaf-recordings
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gowaf-config
  namespace: waf
data:
  config.yaml: |
    waf:
      mode: "block"
      max_body: 1048576
      trust_xff: false
    
    rate_limit:
      enabled: true
      rps: 50
      burst: 100
      strategy: "per_ip"
      path_whitelist:
        - "/api/healthz"
        - "/api/metrics"
      auto_ban:
        enabled: true
        strikes: 5
        window: "1m"
        duration: "10m"
    
    server:
      listen: ":8080"
      api_addr: ":8081"
    
    upstream:
      url: "http://backend-service:9000"
      dial_timeout: 3
      idle_timeout: 90
    
    logging:
      level: "info"
      format: "json"
      output: "stdout"
---
apiVersion: v1
kind: Service
metadata:
  name: gowaf
  namespace: waf
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: 8080
      name: waf
    - port: 8081
      targetPort: 8081
      name: api
  selector:
    app: gowaf
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gowaf
  namespace: waf
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "1m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
spec:
  ingressClassName: nginx
  rules:
    - host: waf.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: gowaf
                port:
                  number: 8080
```

```bash
# 部署
kubectl apply -f deployment.yaml

# 查看 pods
kubectl get pods -n waf

# 查看日志
kubectl logs -n waf -l app=gowaf -f
```

---

## systemd 服务

### /etc/systemd/system/gowaf.service

```ini
[Unit]
Description=GoWAF - Web Application Firewall
Documentation=https://github.com/yourrepo/gowaf
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=gowaf
Group=gowaf
WorkingDirectory=/opt/gowaf
ExecStart=/opt/gowaf/gowaf -config /etc/gowaf/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gowaf

# 环境变量
Environment="TZ=Asia/Shanghai"

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/gowaf/recordings /var/log/gowaf
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 安装步骤

```bash
# 创建用户
sudo useradd -r -s /bin/false gowaf

# 创建目录
sudo mkdir -p /opt/gowaf /etc/gowaf /var/log/gowaf
sudo chown gowaf:gowaf /opt/gowaf /var/log/gowaf

# 复制文件
sudo cp gowaf /opt/gowaf/
sudo cp config.yaml.example /etc/gowaf/config.yaml

# 编辑配置
sudo vim /etc/gowaf/config.yaml

# 安装服务
sudo systemctl daemon-reload
sudo systemctl enable gowaf
sudo systemctl start gowaf

# 检查状态
sudo systemctl status gowaf
sudo journalctl -u gowaf -f
```

---

## 反向代理配置

### Nginx (TLS 终止)

```nginx
upstream gowaf_backend {
    server 127.0.0.1:8080;
    keepalive 64;
}

server {
    listen 443 ssl http2;
    server_name waf.example.com;

    # TLS 证书
    ssl_certificate /etc/nginx/ssl/waf.crt;
    ssl_certificate_key /etc/nginx/ssl/waf.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://gowaf_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        
        # 超时设置
        proxy_connect_timeout 3s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        
        # 缓冲设置
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # 限制上传大小
    client_max_body_size 1m;
}
```

---

## 配置管理

### 配置文件结构

详见 [config.yaml.example](../config.yaml.example)

### 热加载

```bash
# SIGHUP 热加载规则文件
kill -HUP $(pidof gowaf)

# API 热更新规则
curl -X PUT http://localhost:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"mode":"detect"}'
```

### 配置验证

```bash
# 启动前验证配置
./gowaf -validate -config config.yaml

# 查看当前配置
curl http://localhost:8081/api/config
```

---

## 后续步骤

- [安全加固指南](./security-hardening.md)
- [性能调优指南](./performance-tuning.md)
- [监控与可观测性](./monitoring.md)
- [API 文档](./openapi.yaml)