package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"identitymirror/server/internal/config"
	"identitymirror/server/internal/db"
	"identitymirror/server/internal/identity"
	"identitymirror/server/internal/logger"
	"identitymirror/server/internal/transport/httpapi"
)

type App struct {
	cfg             config.Config
	logger          *logger.Logger
	database        *db.Database
	migrator        *db.Migrator
	txRunner        *db.TxRunner
	httpServer      *http.Server
	identityService identity.Service
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

	app := &App{
		cfg:             cfg,
		logger:          log,
		database:        database,
		migrator:        migrator,
		txRunner:        db.NewTxRunner(database),
		identityService: identity.NewInMemoryService(),
	}
	handler := httpapi.NewHandler(app, app.identityService)

	mux := http.NewServeMux()
	handler.Register(mux)
	app.httpServer = &http.Server{
		Addr:         ":" + strconv.Itoa(cfg.HTTP.Port),
		Handler:      mux,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}

	return app, nil
}

func (a *App) Start(ctx context.Context) error {
	if err := a.migrator.Run(ctx); err != nil {
		return &Error{Operation: "run migrations", Cause: err}
	}

	a.logger.Info(ctx, "foundation initialized", "env", a.cfg.Environment, "http_addr", a.httpServer.Addr)

	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.logger.Error(context.Background(), "http server stopped", "error", err.Error())
		}
	}()

	return nil
}

func (a *App) Shutdown(ctx context.Context) error {
	a.logger.Info(ctx, "shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, a.cfg.HTTP.ShutdownTimeout)
	defer cancel()

	if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
		return &Error{Operation: "shutdown http server", Cause: err}
	}

	if err := a.database.Close(); err != nil {
		return err
	}

	return nil
}

func (a *App) HealthCheck(ctx context.Context) error {
	return a.database.HealthCheck(ctx)
}

func (a *App) TxRunner() *db.TxRunner {
	return a.txRunner
}
