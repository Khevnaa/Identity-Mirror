package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Migrator struct {
	db        *Database
	directory string
}

func NewMigrator(db *Database, directory string) (*Migrator, error) {
	if db == nil {
		return nil, &Error{Operation: "build migrator", Cause: fmt.Errorf("database is nil")}
	}
	if directory == "" {
		return nil, &Error{Operation: "build migrator", Cause: fmt.Errorf("migrations directory is empty")}
	}
	return &Migrator{db: db, directory: directory}, nil
}

func (m *Migrator) Run(ctx context.Context) error {
	return NewTxRunner(m.db).InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := m.ensureMigrationsTable(ctx, tx); err != nil {
			return err
		}

		entries, err := m.readMigrationFiles()
		if err != nil {
			return err
		}

		applied, err := m.loadAppliedVersions(ctx, tx)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			if _, exists := applied[entry.Version]; exists {
				continue
			}
			if _, err := tx.ExecContext(ctx, entry.SQL); err != nil {
				return &Error{Operation: "execute migration " + entry.Version, Cause: err}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES ($1, now())`, entry.Version); err != nil {
				return &Error{Operation: "record migration " + entry.Version, Cause: err}
			}
		}
		return nil
	})
}

func (m *Migrator) ensureMigrationsTable(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL
		)
	`)
	if err != nil {
		return &Error{Operation: "ensure schema_migrations table", Cause: err}
	}
	return nil
}

func (m *Migrator) loadAppliedVersions(ctx context.Context, tx *sql.Tx) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, &Error{Operation: "query applied migrations", Cause: err}
	}
	defer rows.Close()

	result := make(map[string]struct{})
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, &Error{Operation: "scan migration version", Cause: err}
		}
		result[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{Operation: "iterate migration versions", Cause: err}
	}
	return result, nil
}

type migrationFile struct {
	Version string
	SQL     string
}

func (m *Migrator) readMigrationFiles() ([]migrationFile, error) {
	entries, err := os.ReadDir(m.directory)
	if err != nil {
		return nil, &Error{Operation: "read migrations directory", Cause: err}
	}

	files := make([]migrationFile, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		version := strings.TrimSuffix(name, ".sql")
		if version == "" {
			return nil, &Error{Operation: "parse migration file", Cause: fmt.Errorf("invalid filename: %s", name)}
		}
		bytes, err := os.ReadFile(filepath.Join(m.directory, name))
		if err != nil {
			return nil, &Error{Operation: "read migration " + name, Cause: err}
		}
		files = append(files, migrationFile{Version: version, SQL: string(bytes)})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Version < files[j].Version
	})
	return files, nil
}
