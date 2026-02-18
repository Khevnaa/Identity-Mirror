package db

import (
	"context"
	"database/sql"
	"fmt"
)

type TxRunner struct {
	db *Database
}

type TxFunc func(ctx context.Context, tx *sql.Tx) error

func NewTxRunner(db *Database) *TxRunner {
	return &TxRunner{db: db}
}

func (r *TxRunner) InTx(ctx context.Context, fn TxFunc) error {
	tx, err := r.db.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return &Error{Operation: "begin transaction", Cause: err}
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(ctx, tx); err != nil {
		return &Error{Operation: "transaction body", Cause: err}
	}

	if err := tx.Commit(); err != nil {
		return &Error{Operation: "commit transaction", Cause: err}
	}
	committed = true
	return nil
}

func WithTx(ctx context.Context, runner *TxRunner, fn TxFunc) error {
	if runner == nil {
		return &Error{Operation: "transaction helper", Cause: fmt.Errorf("tx runner is nil")}
	}
	return runner.InTx(ctx, fn)
}
