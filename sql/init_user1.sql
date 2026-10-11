-- 堡垒机用户表 user1
--
-- /api/bastion/users 以及 /api/bastion/users1 读写的就是这张表:
--   GET    /api/bastion/users        列出 user1 全部行
--   POST   /api/bastion/users        插入一行(bcrypt 后的密码)
--   GET    /api/bastion/users/{id}   按 username 或 id 查
--   PUT    /api/bastion/users/{id}   更新行
--   DELETE /api/bastion/users/{id}   删除行
--   (GET/POST/PUT/DELETE /api/bastion/users1 与上相同,操作同一张 user1 表)
--
-- 用法(库名与 gowaf -mysql-dsn 的示例保持一致,按需替换):
--   mysql -h <host> -P <port> -u <user> -p < sql/init_user1.sql
--
-- 表名是 user1,不是 users:同一个库里的用户表可以有 users1 和 user1 两个表，
-- 分别用于不同的用户来源或业务场景。

CREATE DATABASE IF NOT EXISTS myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE myapp;

CREATE TABLE IF NOT EXISTS user1 (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64) NOT NULL UNIQUE COMMENT '用户名',
    password      VARCHAR(255) NOT NULL COMMENT 'bcrypt 加密后的密码',
    role          VARCHAR(20) NOT NULL DEFAULT 'user' COMMENT '角色：admin/user/auditor',
    public_key    TEXT DEFAULT NULL COMMENT 'SSH 公钥',
    assets        LONGTEXT DEFAULT NULL COMMENT '可访问资产 JSON 数组',
    comment       VARCHAR(255) DEFAULT NULL COMMENT '备注',
    created_at    DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    INDEX idx_username (username),
    INDEX idx_user1_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户管理表 (user1)';