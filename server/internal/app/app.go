package app

import (
	"context"
	"fmt"

	"identitymirror/server/internal/config"
	"identitymirror/server/internal/db"
	"identitymirror/server/internal/logger"
)

type App struct {
	cfg      config.Config
	logger   *logger.Logger
	database *db.Database
	migrator *db.Migrator
	txRunner *db.TxRunner
}

type Error struct {
	Operation string
	Cause     error
}

func (e *Error) Error() string {
	return fmt.Sprintf("app %s failed: %v", e.Operation, e.Cause)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, &Error{Operation: "load config", Cause: err}
	}

	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		return nil, &Error{Operation: "build logger", Cause: err}
	}

	database, err := db.New(ctx, cfg.Database)
	if err != nil {
		return nil, &Error{Operation: "connect database", Cause: err}
	}

	migrator, err := db.NewMigrator(database, cfg.Migrate.Directory)
	if err != nil {
		database.Close()
		return nil, &Error{Operation: "build migrator", Cause: err}
	}

	return &App{
		cfg:      cfg,
		logger:   log,
		database: database,
		migrator: migrator,
		txRunner: db.NewTxRunner(database),
	}, nil
}

func (a *App) Start(ctx context.Context) error {
	if err := a.migrator.Run(ctx); err != nil {
		return &Error{Operation: "run migrations", Cause: err}
	}
	a.logger.Info(ctx, "foundation initialized", "env", a.cfg.Environment)
	return nil
}

func (a *App) Shutdown(ctx context.Context) error {
	a.logger.Info(ctx, "shutting down")
	return a.database.Close()
}

func (a *App) HealthCheck(ctx context.Context) error {
	return a.database.HealthCheck(ctx)
}

func (a *App) TxRunner() *db.TxRunner {
	return a.txRunner
}
