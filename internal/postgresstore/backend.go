package postgresstore

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type rowScanner interface {
	Scan(...any) error
}

type rowsScanner interface {
	Close()
	Err() error
	Next() bool
	Scan(...any) error
}

type transaction interface {
	Exec(context.Context, string, ...any) (int64, error)
	Query(context.Context, string, ...any) (rowsScanner, error)
	QueryRow(context.Context, string, ...any) rowScanner
	Commit(context.Context) error
	Rollback(context.Context) error
}

type database interface {
	Begin(context.Context) (transaction, error)
	Ping(context.Context) error
	Query(context.Context, string, ...any) (rowsScanner, error)
	QueryRow(context.Context, string, ...any) rowScanner
	Close()
}

type poolDatabase struct {
	pool *pgxpool.Pool
}

func (p *poolDatabase) Begin(ctx context.Context) (transaction, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	return pgxTransaction{tx: tx}, nil
}

func (p *poolDatabase) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *poolDatabase) Query(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	return p.pool.Query(ctx, query, args...)
}

func (p *poolDatabase) QueryRow(ctx context.Context, query string, args ...any) rowScanner {
	return p.pool.QueryRow(ctx, query, args...)
}

func (p *poolDatabase) Close() { p.pool.Close() }

type pgxTransaction struct {
	tx pgx.Tx
}

func (t pgxTransaction) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	tag, err := t.tx.Exec(ctx, query, args...)
	return tag.RowsAffected(), err
}

func (t pgxTransaction) Query(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	return t.tx.Query(ctx, query, args...)
}

func (t pgxTransaction) QueryRow(ctx context.Context, query string, args ...any) rowScanner {
	return t.tx.QueryRow(ctx, query, args...)
}

func (t pgxTransaction) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t pgxTransaction) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }
