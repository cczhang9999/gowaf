package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"log/slog"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gowaf/models"
)

// slogGormLogger implements gorm.io/gorm/logger.Interface by delegating to
// slog, so SQL logs are emitted as structured JSON through the same pipeline
// as the rest of the application.
//
// Unlike the default GORM logger (which writes raw lines to os.Stderr via the
// standard library log package), this adapter preserves structured attributes
// such as the SQL statement, row count, duration, and any error.
type slogGormLogger struct {
	level          logger.LogLevel
	log            *slog.Logger
	ignoreNotFound bool
	slowThreshold  time.Duration
}

// NewSlogGormLogger creates a GORM logger that writes structured logs to the
// given slog.Logger. All SQL statements are logged at Info level; slow queries
// (> slowThreshold) at Warn; errors at Error level.
func NewSlogGormLogger(log *slog.Logger) logger.Interface {
	return &slogGormLogger{
		level:          logger.Info,
		log:            log,
		ignoreNotFound: true,
		slowThreshold:  2 * time.Second,
	}
}

// LogMode implements logger.Interface.
func (l *slogGormLogger) LogMode(level logger.LogLevel) logger.Interface {
	newLogger := *l
	newLogger.level = level
	return &newLogger
}

// Info implements logger.Interface.
func (l *slogGormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if l.level >= logger.Info {
		l.log.Info(msg, data...)
	}
}

// Warn implements logger.Interface.
func (l *slogGormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if l.level >= logger.Warn {
		l.log.Warn(msg, data...)
	}
}

// Error implements logger.Interface.
func (l *slogGormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if l.level >= logger.Error {
		l.log.Error(msg, data...)
	}
}

// Trace implements logger.Interface. It is called for every SQL statement
// executed by GORM and logs the query text, execution time, row count, and
// any error at the appropriate level.
func (l *slogGormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.level <= logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	attrs := []any{
		"sql", sql,
		"duration_ms", float64(elapsed.Nanoseconds()) / 1e6,
	}
	if rows != -1 {
		attrs = append(attrs, "rows", rows)
	}

	switch {
	case err != nil:
		if !l.ignoreNotFound || !errors.Is(err, gorm.ErrRecordNotFound) {
			attrs = append(attrs, "err", err)
			l.log.Error("gorm query error", attrs...)
		} else {
			l.log.Debug("gorm query (record not found)", attrs...)
		}
	case elapsed > l.slowThreshold && l.slowThreshold != 0 && l.level >= logger.Warn:
		l.log.Warn("gorm slow query", attrs...)
	default:
		l.log.Info("gorm query", attrs...)
	}
}

type DBClient struct {
	DB *gorm.DB
}

// NewDBClient creates and initializes the database connection.
//
// The provided slog.Logger is used for GORM's SQL trace logging so that all
// queries are visible as structured JSON alongside the rest of the application
// logs.
//
// User table (users1) already exists is not modified; only created when missing;
// see EnsureUserTable.
func NewDBClient(dsn string, log *slog.Logger) (*DBClient, error) {
	if log == nil {
		log = slog.Default()
	}
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: dsn}), &gorm.Config{
		Logger: NewSlogGormLogger(log),
	})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}
	if err := EnsureUserTable(db); err != nil {
		return nil, err
	}
	return &DBClient{DB: db}, nil
}

// EnsureUserTable creates the users1 table when it does not exist; if it
// already exists the existing table is left unchanged.
//
// This deliberately avoids db.AutoMigrate: users1 is typically a pre-existing
// production table (schema in sql/init_users.sql). AutoMigrate would try to
// "align" column types/comments and can emit DROP FOREIGN KEY statements that
// may not run. Table creation is handled by sql/init_users.sql or CreateTable;
// schema changes should be done manually.
func EnsureUserTable(db *gorm.DB) error {
	migrator := db.Migrator()
	if migrator.HasTable(&models.User{}) {
		return nil
	}
	if err := migrator.CreateTable(&models.User{}); err != nil {
		return fmt.Errorf("create %s table: %w", models.UserTableName, err)
	}
	return nil
}

// EnsureUser1Table creates the user1 table when it does not exist; if it
// already exists the existing table is left unchanged.
func EnsureUser1Table(db *gorm.DB) error {
	migrator := db.Migrator()
	if migrator.HasTable(&models.User1{}) {
		return nil
	}
	if err := migrator.CreateTable(&models.User1{}); err != nil {
		return fmt.Errorf("create %s table: %w", models.User1TableName, err)
	}
	return nil
}
