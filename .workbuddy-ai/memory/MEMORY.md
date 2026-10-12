# gowaf 项目长期备忘

## 项目定位
Go 写的迷你 WAF（反向代理式）+ SSH 堡垒机管理面；前端是 Vue3 + Element Plus 的
管理控制台（`web/`），后端管理 API 默认监听 `:8081`，前端 dev 代理 `/api` → 8081。

## 关键约定
- **用户表有两张，别混**（2026-10-12 起控制台统一走 users1）：
  - `users1` —— 控制台「用户管理」页读写（`/api/bastion/users`），也是 SSH 登录认证表，
    两边现在是同一张表。
  - `user1` —— 遗留表，只有旧的 `/api/bastion/users1` 接口还在读写它，勿再用于新功能。
  - `users` —— 业务方无关表（id/name/email），任何 GORM 模型都不要映射到它。
- 数据库：`myapp` 库，DSN 见根目录 `config.yaml`（`hobart@78.154.103.23:9257`）。
- 建表脚本：`sql/init_users.sql`（users1）、`sql/init_user1.sql`（user1，遗留）。
  代码里刻意不用 `AutoMigrate`，避免对线上表反复 ALTER。
- 明文密码统一 bcrypt（`models.HashPassword`），任何响应都不返回 password。

## 常用调试工具（已提交在仓库里）
- `.dbsql` —— 通用 SQL 执行器：`go run ./.dbsql "SELECT ..."`
- `.dbinspect` —— 快照 users1 结构与行数（不打印密钥）
- `.sshtry` —— SSH 密码认证连通性测试
- 注意：`go test ./...` 会扫到 `web/node_modules/flatted/golang/pkg/flatted`，属噪音。

## 运行
```bash
./gowaf -config config.yaml            # WAF + 管理面，用户数据落 myapp.users1
./gowaf -listen :8080 -upstream http://127.0.0.1:9000 -api-addr :8081   # 无 DB，内存模式
cd web && npm install && npm run dev   # 控制台 http://localhost:3000
```
- 配置了 `-mysql-dsn` 时数据库连不上会**启动即 fatal**（fail-fast 设计，非 bug）。
- 启动时只创建不存在的表，已存在的表不动。
- **不带 `-config config.yaml` / `-mysql-dsn` 启动 = 内存模式**：`/api/bastion/users`
  返回 201 但不落任何表，页面「数据来源」显示 memory。排查这类问题先看这个标签。

## 前端约定
- 颜色一律走 CSS 变量（`web/src/assets/styles/index.css`），浅色默认 + `.dark-theme` 覆盖；
  深色模式通过 `<html>` 上的 `.dark-theme` 类切换。
- 页面复用类：`.page-wrapper` / `.page-head`（标题+副标题+操作区）/ `.stat-grid`+
  `.stat-tile`（统计磁贴，`tone-*` 控制图标底色）/ `.toolbar` / `.panel` / `.empty-state` /
  `.source-chip` / `.mono`。新页面优先复用，别各写各的 padding 和卡片样式。
- 图标按需从 `@element-plus/icons-vue` 显式 import。
