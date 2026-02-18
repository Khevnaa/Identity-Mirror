package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"identitymirror/server/internal/config"
)

type Database struct {
	conn         *sql.DB
	queryTimeout time.Duration
	healthTO     time.Duration
}

type Error struct {
	Operation string
	Cause     error
}

func (e *Error) Error() string {
	return fmt.Sprintf("db %s failed: %v", e.Operation, e.Cause)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func New(ctx context.Context, cfg config.DatabaseConfig) (*Database, error) {
	db, err := sql.Open("postgres", cfg.URL)
	if err != nil {
		return nil, &Error{Operation: "open connection", Cause: err}
	}

	db.SetMaxOpenConns(int(cfg.MaxConns))
	db.SetMaxIdleConns(int(cfg.MinConns))
	db.SetConnMaxLifetime(cfg.MaxConnLifetime)
	db.SetConnMaxIdleTime(cfg.MaxConnIdleTime)

	instance := &Database{conn: db, queryTimeout: cfg.QueryTimeout, healthTO: cfg.HealthCheckTimeout}
	if err := instance.HealthCheck(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return instance, nil
}

func (d *Database) Conn() *sql.DB {
	return d.conn
}

func (d *Database) QueryTimeout() time.Duration {
	return d.queryTimeout
}

func (d *Database) HealthCheck(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, d.healthTO)
	defer cancel()
	if err := d.conn.PingContext(hctx); err != nil {
		return &Error{Operation: "health check ping", Cause: err}
	}
	return nil
}

func (d *Database) Close() error {
	if err := d.conn.Close(); err != nil {
		return &Error{Operation: "close", Cause: err}
	}
	return nil
}
