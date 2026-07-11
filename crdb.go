package alias

import (
	"context"
	"errors"
	"time"

	errs "github.com/gomatic/go-error"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// querier is the subset of *pgxpool.Pool that CockroachStore needs. It exists
// so the store's query-building and row-scanning logic is unit-testable with a
// fake, leaving the production driver as the only adapter boundary.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const (
	uniqueViolationCode = "23505"

	insertAliasSQL = `INSERT INTO aliases (subdomain, domain, sender_domain, user_id, active, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`
	selectBySubdomainSQL = `SELECT subdomain, domain, sender_domain, user_id, active, created_at, disabled_at, expires_at
			 FROM aliases WHERE subdomain = $1`
	selectByUserSQL = `SELECT subdomain, domain, sender_domain, user_id, active, created_at, disabled_at, expires_at
			 FROM aliases WHERE user_id = $1 ORDER BY created_at DESC`
	disableAliasSQL   = `UPDATE aliases SET active = false, disabled_at = now() WHERE subdomain = $1 AND active = true`
	deleteAliasSQL    = `DELETE FROM aliases WHERE subdomain = $1`
	countActiveSQL    = `SELECT COUNT(*) FROM aliases WHERE user_id = $1 AND active = true`
	deleteByUserSQL   = `DELETE FROM aliases WHERE user_id = $1`
	findExpiredNowSQL = `SELECT subdomain, domain, sender_domain, user_id, active, created_at, disabled_at, expires_at
			 FROM aliases WHERE active = true AND expires_at IS NOT NULL AND expires_at < now()`
	findExpiredAsOfSQL = `SELECT subdomain, domain, sender_domain, user_id, active, created_at, disabled_at, expires_at
			 FROM aliases WHERE active = true AND expires_at IS NOT NULL AND expires_at < $1`
	listActiveSQL = `SELECT subdomain, domain, sender_domain, user_id, active, created_at, disabled_at, expires_at
			 FROM aliases WHERE active = true`
)

// CockroachStore is a Store backed by CockroachDB over pgx. It is an immutable
// value wrapping the injected querier handle.
type CockroachStore struct {
	db querier
}

func NewCockroachStore(pool *pgxpool.Pool) CockroachStore {
	return CockroachStore{db: pool}
}

func (s CockroachStore) Create(ctx context.Context, a Alias) error {
	count, err := s.CountActiveByUser(ctx, a.UserID)
	if err != nil {
		return ErrCheckAliasCount.With(err)
	}
	if count >= MaxAliasesPerUser {
		return ErrAliasLimitReached
	}

	_, err = s.db.Exec(
		ctx, insertAliasSQL,
		a.Subdomain, a.Domain, a.SenderDomain, a.UserID, a.Enabled, a.ExpiresAt,
	)
	return classifyInsertError(err)
}

// classifyInsertError maps a unique-violation to ErrAliasDuplicate and wraps any
// other failure, keeping the Create body's complexity low.
func classifyInsertError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode {
		return ErrAliasDuplicate
	}
	return ErrInsertAlias.With(err)
}

func (s CockroachStore) GetBySubdomain(ctx context.Context, subdomain string) (*Alias, error) {
	a, err := scanAlias(s.db.QueryRow(ctx, selectBySubdomainSQL, subdomain))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAliasNotFound
	}
	if err != nil {
		return nil, ErrQueryAlias.With(err)
	}
	return &a, nil
}

func (s CockroachStore) ListByUser(ctx context.Context, userID string) ([]*Alias, error) {
	rows, err := s.db.Query(ctx, selectByUserSQL, userID)
	if err != nil {
		return nil, ErrListAliases.With(err)
	}
	defer rows.Close()
	return scanAliases(rows, ErrScanAlias)
}

// ListActive returns every active alias across all users, for the degradation
// sweep that re-validates each alias's sender domain.
func (s CockroachStore) ListActive(ctx context.Context) ([]*Alias, error) {
	rows, err := s.db.Query(ctx, listActiveSQL)
	if err != nil {
		return nil, ErrListAliases.With(err)
	}
	defer rows.Close()
	return scanAliases(rows, ErrScanAlias)
}

func (s CockroachStore) Disable(ctx context.Context, subdomain string) error {
	return s.execAffecting(ctx, ErrDisableAlias, disableAliasSQL, subdomain)
}

func (s CockroachStore) Delete(ctx context.Context, subdomain string) error {
	return s.execAffecting(ctx, ErrDeleteAlias, deleteAliasSQL, subdomain)
}

// execAffecting runs a statement that must touch at least one row, mapping a
// zero-row result to ErrAliasNotFound and any driver failure to the given sentinel.
func (s CockroachStore) execAffecting(ctx context.Context, wrap errs.Const, sql string, args ...any) error {
	tag, err := s.db.Exec(ctx, sql, args...)
	if err != nil {
		return wrap.With(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAliasNotFound
	}
	return nil
}

func (s CockroachStore) CountActiveByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, countActiveSQL, userID).Scan(&count)
	if err != nil {
		return 0, ErrCountAliases.With(err)
	}
	return count, nil
}

func (s CockroachStore) DeleteByUser(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, deleteByUserSQL, userID)
	if err != nil {
		return ErrDeleteUserAliases.With(err)
	}
	return nil
}

func (s CockroachStore) FindExpired(ctx context.Context) ([]*Alias, error) {
	return s.findExpired(ctx, findExpiredNowSQL)
}

func (s CockroachStore) FindExpiredAsOf(ctx context.Context, cutoff time.Time) ([]*Alias, error) {
	return s.findExpired(ctx, findExpiredAsOfSQL, cutoff)
}

func (s CockroachStore) findExpired(ctx context.Context, sql string, args ...any) ([]*Alias, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, ErrFindExpired.With(err)
	}
	defer rows.Close()
	return scanAliases(rows, ErrScanExpired)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanAlias reads one aliases row and returns it by value.
func scanAlias(row rowScanner) (Alias, error) {
	var a Alias
	err := row.Scan(
		&a.Subdomain, &a.Domain, &a.SenderDomain, &a.UserID,
		&a.Enabled, &a.CreatedAt, &a.DisabledAt, &a.ExpiresAt,
	)
	return a, err
}

// scanAliases drains rows into a slice, wrapping scan failures in the given
// sentinel and surfacing any iteration error.
func scanAliases(rows pgx.Rows, scanErr errs.Const) ([]*Alias, error) {
	var aliases []*Alias
	for rows.Next() {
		a, err := scanAlias(rows)
		if err != nil {
			return nil, scanErr.With(err)
		}
		aliases = append(aliases, &a)
	}
	return aliases, rows.Err()
}
