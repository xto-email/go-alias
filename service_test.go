package alias

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xto-email/go-clock"
	"github.com/xto-email/go-domainsec"
)

// fakeStore is an in-memory Store that records calls and returns
// preconfigured results, letting Service logic be unit-tested without a DB.
type fakeStore struct {
	createErr      error
	listErr        error
	getErr         error
	disableErr     error
	findExpiredErr error
	listActiveErr  error
	getResult      *Alias
	listResult     []*Alias
	created        []*Alias
	disabled       []string
	findExpired    []*Alias
	listActive     []*Alias
}

func (f *fakeStore) Create(_ context.Context, a Alias) error {
	f.created = append(f.created, &a)
	return f.createErr
}

func (f *fakeStore) GetBySubdomain(_ context.Context, _ string) (*Alias, error) {
	return f.getResult, f.getErr
}

func (f *fakeStore) ListActive(_ context.Context) ([]*Alias, error) {
	return f.listActive, f.listActiveErr
}

func (f *fakeStore) ListByUser(_ context.Context, _ string) ([]*Alias, error) {
	return f.listResult, f.listErr
}

func (f *fakeStore) Disable(_ context.Context, subdomain string) error {
	f.disabled = append(f.disabled, subdomain)
	return f.disableErr
}

func (f *fakeStore) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeStore) CountActiveByUser(_ context.Context, _ string) (int, error) { return 0, nil }

func (f *fakeStore) DeleteByUser(_ context.Context, _ string) error { return nil }

func (f *fakeStore) FindExpired(_ context.Context) ([]*Alias, error) {
	return f.findExpired, f.findExpiredErr
}

func (f *fakeStore) FindExpiredAsOf(_ context.Context, _ time.Time) ([]*Alias, error) {
	return f.findExpired, f.findExpiredErr
}

// fakeChecker is a domainChecker double returning a fixed report/error.
type fakeChecker struct {
	report *domainsec.DomainSecurityReport
	err    error
}

func (f fakeChecker) CheckDomain(_ context.Context, _ string) (*domainsec.DomainSecurityReport, error) {
	return f.report, f.err
}

func secureReport() *domainsec.DomainSecurityReport {
	return &domainsec.DomainSecurityReport{
		HasDKIM:     true,
		HasDMARC:    true,
		DMARCPolicy: domainsec.DMARCPolicy("reject"),
	}
}

func insecureReport() *domainsec.DomainSecurityReport {
	return &domainsec.DomainSecurityReport{HasDKIM: false}
}

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newService wires a Service with the given collaborators and a fake clock.
func newService(store Store, checker domainChecker, key []byte) Service {
	return Service{
		store:      store,
		domainSvc:  checker,
		secretKeys: [][]byte{key},
		logger:     discardLogger(),
		clk:        clock.NewFake(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
	}
}

func TestPrimaryKey_EmptyRingIsNil(t *testing.T) {
	if (Service{}).primaryKey() != nil {
		t.Fatal("an empty key ring must yield a nil primary key (Generate then fails closed)")
	}
}

// TestExpiryUsesInjectedClock pins burnerExpiry to the injected clock: the
// burner expiry must be derived from the service clock, never the wall clock.
func TestExpiryUsesInjectedClock(t *testing.T) {
	anchor := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	svc := Service{clk: clock.NewFake(anchor)}

	exp := svc.burnerExpiry()
	want := anchor.Add(7 * 24 * time.Hour)
	if !exp.Equal(want) {
		t.Fatalf("burnerExpiry() = %v, want %v", exp, want)
	}
}

func TestNewService_NilClockDefaultsToSystem(t *testing.T) {
	svc := NewService(&fakeStore{}, nil, nil, discardLogger(), nil)
	_, ok := svc.clk.(clock.System)
	assert.True(t, ok)
}

func TestNewService_KeepsProvidedClock(t *testing.T) {
	fake := clock.NewFake(time.Now())
	svc := NewService(&fakeStore{}, nil, nil, discardLogger(), fake)
	assert.Same(t, fake, svc.clk)
}

func TestGenerate_PermanentAlias(t *testing.T) {
	store := &fakeStore{}
	svc := newService(store, fakeChecker{report: secureReport()}, testKey(t))

	a, err := svc.Generate(context.Background(), "example.com", "u", "xto.email")
	require.NoError(t, err)
	assert.Nil(t, a.ExpiresAt)
	assert.Len(t, a.Subdomain, subdomainLength)
	assert.Len(t, store.created, 1)
}

func TestGenerate_BurnerAliasGetsExpiry(t *testing.T) {
	store := &fakeStore{}
	svc := newService(store, fakeChecker{report: secureReport()}, testKey(t))

	a, err := svc.Generate(context.Background(), "example.com", "u", "nix.contact")
	require.NoError(t, err)
	require.NotNil(t, a.ExpiresAt)
	want := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC).Add(7 * 24 * time.Hour)
	assert.True(t, a.ExpiresAt.Equal(want))
}

func TestGenerate_CheckDomainError(t *testing.T) {
	svc := newService(&fakeStore{}, fakeChecker{err: assertErr}, testKey(t))

	_, err := svc.Generate(context.Background(), "example.com", "u", "xto.email")
	assert.ErrorIs(t, err, ErrCheckDomainSecurity)
}

func TestGenerate_GateRejects(t *testing.T) {
	svc := newService(&fakeStore{}, fakeChecker{report: insecureReport()}, testKey(t))

	_, err := svc.Generate(context.Background(), "example.com", "u", "xto.email")
	require.ErrorIs(t, err, ErrDomainSecurity)
	// Contract consumed by internal/api/handlers: leading "domain" and length>20.
	assert.Equal(t, "domain", err.Error()[:6])
	assert.Greater(t, len(err.Error()), 20)
}

func TestGenerate_DeriveError(t *testing.T) {
	// Empty secret key makes Generate (HMAC) fail.
	svc := newService(&fakeStore{}, fakeChecker{report: secureReport()}, nil)

	_, err := svc.Generate(context.Background(), "example.com", "u", "xto.email")
	assert.ErrorIs(t, err, ErrGenerateAlias)
}

func TestGenerate_InvalidAlias(t *testing.T) {
	// An unknown target domain fails Alias.Validate (domain not allowed).
	svc := newService(&fakeStore{}, fakeChecker{report: secureReport()}, testKey(t))

	_, err := svc.Generate(context.Background(), "example.com", "u", "unknown.test")
	assert.ErrorIs(t, err, ErrInvalidAlias)
}

func TestGenerate_StoreError(t *testing.T) {
	store := &fakeStore{createErr: assertErr}
	svc := newService(store, fakeChecker{report: secureReport()}, testKey(t))

	_, err := svc.Generate(context.Background(), "example.com", "u", "xto.email")
	assert.ErrorIs(t, err, ErrStoreAlias)
}

func TestValidateHMAC_Delegates(t *testing.T) {
	key := testKey(t)
	svc := newService(&fakeStore{}, fakeChecker{}, key)

	sub, err := Generate("newsletter.com", key)
	require.NoError(t, err)

	valid, err := svc.ValidateHMAC(Subdomain(sub), "hello@newsletter.com")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestGetBySubdomain_Delegates(t *testing.T) {
	want := &Alias{Subdomain: "sub"}
	svc := newService(&fakeStore{getResult: want}, fakeChecker{}, nil)

	got, err := svc.GetBySubdomain(context.Background(), "sub")
	require.NoError(t, err)
	assert.Same(t, want, got)
}

func TestGetForUser_OwnerMatch(t *testing.T) {
	want := &Alias{Subdomain: "sub", UserID: "u1"}
	svc := newService(&fakeStore{getResult: want}, fakeChecker{}, nil)

	got, err := svc.GetForUser(context.Background(), "u1", "sub")
	require.NoError(t, err)
	assert.Same(t, want, got)
}

func TestGetForUser_OtherOwnerIsNotFound(t *testing.T) {
	// An alias owned by someone else must be indistinguishable from a missing
	// one — the caller learns nothing about another user's alias.
	svc := newService(&fakeStore{getResult: &Alias{Subdomain: "sub", UserID: "owner"}}, fakeChecker{}, nil)

	_, err := svc.GetForUser(context.Background(), "intruder", "sub")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

func TestGetForUser_StoreError(t *testing.T) {
	svc := newService(&fakeStore{getErr: assertErr}, fakeChecker{}, nil)

	_, err := svc.GetForUser(context.Background(), "u1", "sub")
	assert.ErrorIs(t, err, assertErr)
}

func TestDisableForUser_OwnerDisables(t *testing.T) {
	store := &fakeStore{getResult: &Alias{Subdomain: "sub", UserID: "u1"}}
	svc := newService(store, fakeChecker{}, nil)

	require.NoError(t, svc.DisableForUser(context.Background(), "u1", "sub"))
	assert.Equal(t, []string{"sub"}, store.disabled)
}

func TestDisableForUser_OtherOwnerIsNotFoundAndDoesNotDisable(t *testing.T) {
	// The defining guard against the cross-tenant revocation: a non-owner gets
	// ErrAliasNotFound and the underlying Disable is never reached.
	store := &fakeStore{getResult: &Alias{Subdomain: "sub", UserID: "owner"}}
	svc := newService(store, fakeChecker{}, nil)

	err := svc.DisableForUser(context.Background(), "intruder", "sub")
	assert.ErrorIs(t, err, ErrAliasNotFound)
	assert.Empty(t, store.disabled)
}

func TestDisableForUser_StoreError(t *testing.T) {
	svc := newService(&fakeStore{getErr: assertErr}, fakeChecker{}, nil)

	err := svc.DisableForUser(context.Background(), "u1", "sub")
	assert.ErrorIs(t, err, assertErr)
}

func TestActiveBySubdomain_StoreError(t *testing.T) {
	svc := newService(&fakeStore{getErr: assertErr}, fakeChecker{}, nil)

	_, err := svc.ActiveBySubdomain(context.Background(), "sub")
	assert.ErrorIs(t, err, assertErr)
}

func TestActiveBySubdomain_DisabledIsNotFound(t *testing.T) {
	svc := newService(&fakeStore{getResult: &Alias{Subdomain: "sub", Enabled: false}}, fakeChecker{}, nil)

	_, err := svc.ActiveBySubdomain(context.Background(), "sub")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

func TestActiveBySubdomain_ExpiredIsNotFound(t *testing.T) {
	// newService anchors its fake clock at 2026-06-14; an expiry before then is
	// past, so the alias must fail closed even though its stored flag is active.
	expired := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	svc := newService(
		&fakeStore{getResult: &Alias{Subdomain: "sub", Enabled: true, ExpiresAt: &expired}},
		fakeChecker{},
		nil,
	)

	_, err := svc.ActiveBySubdomain(context.Background(), "sub")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

func TestActiveBySubdomain_LiveAliasReturned(t *testing.T) {
	future := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	want := &Alias{Subdomain: "sub", Enabled: true, ExpiresAt: &future}
	svc := newService(&fakeStore{getResult: want}, fakeChecker{}, nil)

	got, err := svc.ActiveBySubdomain(context.Background(), "sub")
	require.NoError(t, err)
	assert.Same(t, want, got)
}

func TestList_Delegates(t *testing.T) {
	want := []*Alias{{Subdomain: "a"}}
	svc := newService(&fakeStore{listResult: want}, fakeChecker{}, nil)

	got, err := svc.List(context.Background(), "u")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestListWithSecurity_Success(t *testing.T) {
	store := &fakeStore{listResult: []*Alias{
		{Subdomain: "a", SenderDomain: "example.com"},
	}}
	svc := newService(store, fakeChecker{report: secureReport()}, nil)

	got, err := svc.ListWithSecurity(context.Background(), "u")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].Alias.Subdomain)
	assert.NotNil(t, got[0].DomainSecurity)
}

func TestListWithSecurity_CheckErrorIsLoggedNotFatal(t *testing.T) {
	// A failing domain-security check must not fail the listing; the alias is
	// returned with a nil security report.
	store := &fakeStore{listResult: []*Alias{{Subdomain: "a", SenderDomain: "example.com"}}}
	svc := newService(store, fakeChecker{err: assertErr}, nil)

	got, err := svc.ListWithSecurity(context.Background(), "u")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].DomainSecurity)
}

func TestListWithSecurity_ListError(t *testing.T) {
	svc := newService(&fakeStore{listErr: assertErr}, fakeChecker{}, nil)

	_, err := svc.ListWithSecurity(context.Background(), "u")
	assert.ErrorIs(t, err, ErrListAliases)
}

func TestServiceDisable_Success(t *testing.T) {
	store := &fakeStore{}
	svc := newService(store, fakeChecker{}, nil)

	require.NoError(t, svc.Disable(context.Background(), "sub"))
	assert.Equal(t, []string{"sub"}, store.disabled)
}

func TestServiceDisable_Error(t *testing.T) {
	svc := newService(&fakeStore{disableErr: assertErr}, fakeChecker{}, nil)

	assert.ErrorIs(t, svc.Disable(context.Background(), "sub"), ErrDisableAlias)
}
