package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"identitymirror/server/internal/app"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		return err
	}

	if err := application.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		if !errors.Is(err, context.Canceled) {
			return err
		}
	}

	return nil
}
