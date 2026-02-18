package logger

import (
	"context"
	"log/slog"
	"os"
)

type Logger struct {
	inner *slog.Logger
}

type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

func New(level string) (*Logger, error) {
	parsed, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed})
	return &Logger{inner: slog.New(handler)}, nil
}

func (l *Logger) Info(ctx context.Context, msg string, attrs ...any) {
	l.inner.InfoContext(ctx, msg, attrs...)
}

func (l *Logger) Error(ctx context.Context, msg string, attrs ...any) {
	l.inner.ErrorContext(ctx, msg, attrs...)
}

func (l *Logger) Debug(ctx context.Context, msg string, attrs ...any) {
	l.inner.DebugContext(ctx, msg, attrs...)
}

func (l *Logger) Warn(ctx context.Context, msg string, attrs ...any) {
	l.inner.WarnContext(ctx, msg, attrs...)
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return 0, &Error{Message: "invalid LOG_LEVEL, expected one of DEBUG|INFO|WARN|ERROR"}
	}
}
