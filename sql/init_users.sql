-- 堡垒机用户表 users1
--
-- SSH 登录认证读写的就是这张表:
--   Authenticate / AuthenticatePublicKey 通过 users1 查表验证密码与公钥。
--
-- 用法(库名与 gowaf -mysql-dsn 的示例保持一致,按需替换):
--   mysql -h <host> -P <port> -u <user> -p < sql/init_users.sql
--
-- 表名是 users1,不是 users:同一个库里的 users 表通常是业务方自己的数据,
-- 不要混用。启动时 GORM AutoMigrate 会自动建表,这里只是显式版本。

CREATE DATABASE IF NOT EXISTS myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE myapp;

CREATE TABLE IF NOT EXISTS users1 (
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
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户管理表';
