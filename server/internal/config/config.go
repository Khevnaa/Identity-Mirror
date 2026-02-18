package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment string
	LogLevel    string

	Database DatabaseConfig
	Migrate  MigrationConfig
}

type DatabaseConfig struct {
	URL                string
	MaxConns           int32
	MinConns           int32
	MaxConnLifetime    time.Duration
	MaxConnIdleTime    time.Duration
	HealthCheckPeriod  time.Duration
	ConnectTimeout     time.Duration
	QueryTimeout       time.Duration
	HealthCheckTimeout time.Duration
}

type MigrationConfig struct {
	Directory string
}

type Error struct {
	Field   string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("config error: %s: %s", e.Field, e.Message)
}

func Load() (Config, error) {
	env, err := requiredString("APP_ENV")
	if err != nil {
		return Config{}, err
	}
	logLevel, err := requiredString("LOG_LEVEL")
	if err != nil {
		return Config{}, err
	}
	dbURL, err := requiredString("DB_URL")
	if err != nil {
		return Config{}, err
	}

	maxConns, err := requiredInt32("DB_MAX_CONNS")
	if err != nil {
		return Config{}, err
	}
	minConns, err := requiredInt32("DB_MIN_CONNS")
	if err != nil {
		return Config{}, err
	}
	if minConns < 0 {
		return Config{}, &Error{Field: "DB_MIN_CONNS", Message: "must be >= 0"}
	}
	if maxConns < 1 {
		return Config{}, &Error{Field: "DB_MAX_CONNS", Message: "must be >= 1"}
	}
	if minConns > maxConns {
		return Config{}, &Error{Field: "DB_MIN_CONNS", Message: "must be <= DB_MAX_CONNS"}
	}

	maxLifetime, err := requiredDuration("DB_MAX_CONN_LIFETIME")
	if err != nil {
		return Config{}, err
	}
	maxIdle, err := requiredDuration("DB_MAX_CONN_IDLE_TIME")
	if err != nil {
		return Config{}, err
	}
	healthPeriod, err := requiredDuration("DB_HEALTH_CHECK_PERIOD")
	if err != nil {
		return Config{}, err
	}
	connectTimeout, err := requiredDuration("DB_CONNECT_TIMEOUT")
	if err != nil {
		return Config{}, err
	}
	queryTimeout, err := requiredDuration("DB_QUERY_TIMEOUT")
	if err != nil {
		return Config{}, err
	}
	healthTimeout, err := requiredDuration("DB_HEALTH_CHECK_TIMEOUT")
	if err != nil {
		return Config{}, err
	}

	if maxLifetime <= 0 || maxIdle <= 0 || healthPeriod <= 0 || connectTimeout <= 0 || queryTimeout <= 0 || healthTimeout <= 0 {
		return Config{}, &Error{Field: "DB_*", Message: "all durations must be > 0"}
	}

	migrationsDir, err := requiredString("MIGRATIONS_DIR")
	if err != nil {
		return Config{}, err
	}

	return Config{
		Environment: env,
		LogLevel:    logLevel,
		Database: DatabaseConfig{
			URL:                dbURL,
			MaxConns:           maxConns,
			MinConns:           minConns,
			MaxConnLifetime:    maxLifetime,
			MaxConnIdleTime:    maxIdle,
			HealthCheckPeriod:  healthPeriod,
			ConnectTimeout:     connectTimeout,
			QueryTimeout:       queryTimeout,
			HealthCheckTimeout: healthTimeout,
		},
		Migrate: MigrationConfig{Directory: migrationsDir},
	}, nil
}

func requiredString(key string) (string, error) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return "", &Error{Field: key, Message: "is required"}
	}
	return value, nil
}

func requiredInt32(key string) (int32, error) {
	value, err := requiredString(key)
	if err != nil {
		return 0, err
	}
	parsed, parseErr := strconv.ParseInt(value, 10, 32)
	if parseErr != nil {
		return 0, &Error{Field: key, Message: "must be a valid int32"}
	}
	return int32(parsed), nil
}

func requiredDuration(key string) (time.Duration, error) {
	value, err := requiredString(key)
	if err != nil {
		return 0, err
	}
	duration, parseErr := time.ParseDuration(value)
	if parseErr != nil {
		return 0, &Error{Field: key, Message: "must be a valid duration"}
	}
	return duration, nil
}
