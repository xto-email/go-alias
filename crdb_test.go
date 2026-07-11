package alias

import (
	"context"
	"testing"
	"time"

	errs "github.com/gomatic/go-error"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertErr is a generic non-sentinel error used to drive store error paths.
const assertErr errs.Const = "boom"

// fakeQuerier is a test double for the querier interface. Each method returns
// the preconfigured value, capturing the SQL and args for assertions.
type fakeQuerier struct {
	execTag pgconn.CommandTag
	execErr error

	queryRows pgx.Rows
	queryErr  error

	row pgx.Row

	// rowQueue lets a single test serve different rows across successive
	// QueryRow calls (e.g. Create's count followed by an insert path).
	rowQueue []pgx.Row

	gotSQL  string
	gotArgs []any
	execN   int
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.gotSQL = sql
	f.gotArgs = args
	f.execN++
	return f.execTag, f.execErr
}

func (f *fakeQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.gotSQL = sql
	f.gotArgs = args
	return f.queryRows, f.queryErr
}

func (f *fakeQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.gotSQL = sql
	f.gotArgs = args
	if len(f.rowQueue) > 0 {
		r := f.rowQueue[0]
		f.rowQueue = f.rowQueue[1:]
		return r
	}
	return f.row
}

// fakeRow implements pgx.Row.
type fakeRow struct {
	scanErr error
	fill    func(dest ...any)
}

func (r fakeRow) Scan(dest ...any) error {
	if r.fill != nil {
		r.fill(dest...)
	}
	return r.scanErr
}

// fakeRows implements pgx.Rows by embedding the interface (unused methods stay
// nil and are never invoked by the store) and overriding the four methods the
// store actually calls.
type fakeRows struct {
	pgx.Rows
	scanErr error
	err     error
	scans   []func(dest ...any)
	idx     int
	closed  bool
}

func (r *fakeRows) Close()     { r.closed = true }
func (r *fakeRows) Err() error { return r.err }

func (r *fakeRows) Next() bool { return r.idx < len(r.scans) }

func (r *fakeRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	r.scans[r.idx](dest...)
	r.idx++
	return nil
}

func newStore(q querier) CockroachStore {
	return CockroachStore{db: q}
}

// countRow yields a single COUNT(*) scalar.
func countRow(n int) fakeRow {
	return fakeRow{fill: func(dest ...any) { *dest[0].(*int) = n }}
}

// fillAlias populates the eight Scan destinations for an aliases row.
func fillAlias(dest []any, subdomain, domain, sender string) {
	*dest[0].(*string) = subdomain
	*dest[1].(*string) = domain
	*dest[2].(*string) = sender
	*dest[3].(*string) = "u"
	*dest[4].(*bool) = true
	*dest[5].(*time.Time) = time.Now().UTC()
	// disabled_at (dest[6]) and expires_at (dest[7]) are *time.Time pointers,
	// left nil by the driver for these rows.
}

func TestNewCockroachStore(t *testing.T) {
	require.NotNil(t, NewCockroachStore(nil))
}

func TestCreate_Success(t *testing.T) {
	q := &fakeQuerier{rowQueue: []pgx.Row{countRow(0)}}
	s := newStore(q)

	err := s.Create(context.Background(), Alias{UserID: "u", Subdomain: "sub"})
	require.NoError(t, err)
	assert.Equal(t, insertAliasSQL, q.gotSQL)
	assert.Equal(t, 1, q.execN)
}

func TestCreate_CountError(t *testing.T) {
	q := &fakeQuerier{rowQueue: []pgx.Row{fakeRow{scanErr: assertErr}}}
	s := newStore(q)

	err := s.Create(context.Background(), Alias{UserID: "u"})
	assert.ErrorIs(t, err, ErrCheckAliasCount)
}

func TestCreate_LimitReached(t *testing.T) {
	q := &fakeQuerier{rowQueue: []pgx.Row{countRow(MaxAliasesPerUser)}}
	s := newStore(q)

	err := s.Create(context.Background(), Alias{UserID: "u"})
	assert.ErrorIs(t, err, ErrAliasLimitReached)
	assert.Equal(t, 0, q.execN)
}

func TestCreate_Duplicate(t *testing.T) {
	q := &fakeQuerier{
		rowQueue: []pgx.Row{countRow(0)},
		execErr:  &pgconn.PgError{Code: uniqueViolationCode},
	}
	s := newStore(q)

	err := s.Create(context.Background(), Alias{UserID: "u"})
	assert.ErrorIs(t, err, ErrAliasDuplicate)
}

func TestCreate_InsertError(t *testing.T) {
	q := &fakeQuerier{
		rowQueue: []pgx.Row{countRow(0)},
		execErr:  assertErr,
	}
	s := newStore(q)

	err := s.Create(context.Background(), Alias{UserID: "u"})
	assert.ErrorIs(t, err, ErrInsertAlias)
}

func TestClassifyInsertError_OtherPgError(t *testing.T) {
	err := classifyInsertError(&pgconn.PgError{Code: "12345"})
	assert.ErrorIs(t, err, ErrInsertAlias)
}

func TestGetBySubdomain_Success(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{fill: func(dest ...any) {
		fillAlias(dest, "abc123def456ghi7", "xto.email", "example.com")
	}}}
	s := newStore(q)

	a, err := s.GetBySubdomain(context.Background(), "abc123def456ghi7")
	require.NoError(t, err)
	assert.Equal(t, "abc123def456ghi7", a.Subdomain)
	assert.Equal(t, selectBySubdomainSQL, q.gotSQL)
}

func TestGetBySubdomain_NotFound(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{scanErr: pgx.ErrNoRows}}
	s := newStore(q)

	_, err := s.GetBySubdomain(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

func TestGetBySubdomain_OtherError(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{scanErr: assertErr}}
	s := newStore(q)

	_, err := s.GetBySubdomain(context.Background(), "sub")
	assert.ErrorIs(t, err, ErrQueryAlias)
}

func TestListByUser_Success(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){
		func(dest ...any) { fillAlias(dest, "a", "xto.email", "e.com") },
		func(dest ...any) { fillAlias(dest, "b", "xto.email", "e.com") },
	}}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	aliases, err := s.ListByUser(context.Background(), "u")
	require.NoError(t, err)
	assert.Len(t, aliases, 2)
	assert.Equal(t, selectByUserSQL, q.gotSQL)
	assert.True(t, rows.closed)
}

func TestListActive_Success(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){
		func(dest ...any) { fillAlias(dest, "a", "xto.email", "e.com") },
	}}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	aliases, err := s.ListActive(context.Background())
	require.NoError(t, err)
	assert.Len(t, aliases, 1)
	assert.Equal(t, listActiveSQL, q.gotSQL)
	assert.True(t, rows.closed)
}

func TestListActive_QueryError(t *testing.T) {
	q := &fakeQuerier{queryErr: assertErr}
	s := newStore(q)

	_, err := s.ListActive(context.Background())
	assert.ErrorIs(t, err, ErrListAliases)
}

func TestListByUser_QueryError(t *testing.T) {
	q := &fakeQuerier{queryErr: assertErr}
	s := newStore(q)

	_, err := s.ListByUser(context.Background(), "u")
	assert.ErrorIs(t, err, ErrListAliases)
}

func TestListByUser_ScanError(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){func(_ ...any) {}}, scanErr: assertErr}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	_, err := s.ListByUser(context.Background(), "u")
	assert.ErrorIs(t, err, ErrScanAlias)
}

func TestListByUser_RowsErr(t *testing.T) {
	rows := &fakeRows{err: assertErr}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	_, err := s.ListByUser(context.Background(), "u")
	assert.ErrorIs(t, err, assertErr)
}

func TestDisable_Success(t *testing.T) {
	q := &fakeQuerier{execTag: pgconn.NewCommandTag("UPDATE 1")}
	s := newStore(q)

	require.NoError(t, s.Disable(context.Background(), "sub"))
	assert.Equal(t, disableAliasSQL, q.gotSQL)
}

func TestDisable_NotFound(t *testing.T) {
	q := &fakeQuerier{execTag: pgconn.NewCommandTag("UPDATE 0")}
	s := newStore(q)

	assert.ErrorIs(t, s.Disable(context.Background(), "sub"), ErrAliasNotFound)
}

func TestDisable_Error(t *testing.T) {
	q := &fakeQuerier{execErr: assertErr}
	s := newStore(q)

	assert.ErrorIs(t, s.Disable(context.Background(), "sub"), ErrDisableAlias)
}

func TestDelete_Success(t *testing.T) {
	q := &fakeQuerier{execTag: pgconn.NewCommandTag("DELETE 1")}
	s := newStore(q)

	require.NoError(t, s.Delete(context.Background(), "sub"))
	assert.Equal(t, deleteAliasSQL, q.gotSQL)
}

func TestDelete_NotFound(t *testing.T) {
	q := &fakeQuerier{execTag: pgconn.NewCommandTag("DELETE 0")}
	s := newStore(q)

	assert.ErrorIs(t, s.Delete(context.Background(), "sub"), ErrAliasNotFound)
}

func TestDelete_Error(t *testing.T) {
	q := &fakeQuerier{execErr: assertErr}
	s := newStore(q)

	assert.ErrorIs(t, s.Delete(context.Background(), "sub"), ErrDeleteAlias)
}

func TestCountActiveByUser_Success(t *testing.T) {
	q := &fakeQuerier{row: countRow(7)}
	s := newStore(q)

	n, err := s.CountActiveByUser(context.Background(), "u")
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	assert.Equal(t, countActiveSQL, q.gotSQL)
}

func TestCountActiveByUser_Error(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{scanErr: assertErr}}
	s := newStore(q)

	_, err := s.CountActiveByUser(context.Background(), "u")
	assert.ErrorIs(t, err, ErrCountAliases)
}

func TestDeleteByUser_Success(t *testing.T) {
	q := &fakeQuerier{}
	s := newStore(q)

	require.NoError(t, s.DeleteByUser(context.Background(), "u"))
	assert.Equal(t, deleteByUserSQL, q.gotSQL)
}

func TestDeleteByUser_Error(t *testing.T) {
	q := &fakeQuerier{execErr: assertErr}
	s := newStore(q)

	assert.ErrorIs(t, s.DeleteByUser(context.Background(), "u"), ErrDeleteUserAliases)
}

func TestFindExpired_Success(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){
		func(dest ...any) { fillAlias(dest, "a", "nix.contact", "e.com") },
	}}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	got, err := s.FindExpired(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, findExpiredNowSQL, q.gotSQL)
}

func TestFindExpired_QueryError(t *testing.T) {
	q := &fakeQuerier{queryErr: assertErr}
	s := newStore(q)

	_, err := s.FindExpired(context.Background())
	assert.ErrorIs(t, err, ErrFindExpired)
}

func TestFindExpiredAsOf_Success(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){
		func(dest ...any) { fillAlias(dest, "a", "nix.contact", "e.com") },
	}}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	got, err := s.FindExpiredAsOf(context.Background(), time.Now().UTC())
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, findExpiredAsOfSQL, q.gotSQL)
	assert.Len(t, q.gotArgs, 1)
}

func TestFindExpiredAsOf_ScanError(t *testing.T) {
	rows := &fakeRows{scans: []func(dest ...any){func(_ ...any) {}}, scanErr: assertErr}
	q := &fakeQuerier{queryRows: rows}
	s := newStore(q)

	_, err := s.FindExpiredAsOf(context.Background(), time.Now().UTC())
	assert.ErrorIs(t, err, ErrScanExpired)
}
