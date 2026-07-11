package alias

import (
	"context"
	"testing"
	"time"

	"github.com/gomatic/go-clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlias_BurnerMustHaveExpiration(t *testing.T) {
	a := &Alias{
		Subdomain:    "abc123def456ghi7",
		Domain:       "nix.contact",
		SenderDomain: "example.com",
		UserID:       "user-1",
		Enabled:      true,
		ExpiresAt:    nil, // missing for burner
	}
	err := a.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "burner domain aliases must have an expiration")
}

func TestAlias_XtoEmailMustNotHaveExpiration(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour)
	a := &Alias{
		Subdomain:    "abc123def456ghi7",
		Domain:       "xto.email",
		SenderDomain: "example.com",
		UserID:       "user-1",
		Enabled:      true,
		ExpiresAt:    &exp,
	}
	err := a.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "xto.email aliases must not have an expiration")
}

func TestAlias_ValidBurnerAlias(t *testing.T) {
	exp := time.Now().Add(7 * 24 * time.Hour)
	a := &Alias{
		Subdomain:    "abc123def456ghi7",
		Domain:       "nix.contact",
		SenderDomain: "example.com",
		UserID:       "user-1",
		Enabled:      true,
		ExpiresAt:    &exp,
	}
	assert.NoError(t, a.Validate())
}

func TestAlias_ValidPermanentAlias(t *testing.T) {
	a := &Alias{
		Subdomain:    "abc123def456ghi7",
		Domain:       "xto.email",
		SenderDomain: "example.com",
		UserID:       "user-1",
		Enabled:      true,
	}
	assert.NoError(t, a.Validate())
}

func TestAlias_BadSubdomain(t *testing.T) {
	a := &Alias{Subdomain: "TOO-short", Domain: "xto.email", SenderDomain: "e.com"}
	assert.ErrorIs(t, a.Validate(), ErrSubdomainFormat)
}

func TestAlias_DomainNotAllowed(t *testing.T) {
	a := &Alias{Subdomain: "abc123def456ghi7", Domain: "evil.test", SenderDomain: "e.com"}
	assert.ErrorIs(t, a.Validate(), ErrDomainNotAllowed)
}

func TestAlias_SenderDomainNoDot(t *testing.T) {
	a := &Alias{Subdomain: "abc123def456ghi7", Domain: "xto.email", SenderDomain: "nodot"}
	assert.ErrorIs(t, a.Validate(), ErrSenderDomainNoDot)
}

func TestAlias_Address(t *testing.T) {
	a := &Alias{Subdomain: "abc123def456ghi7", Domain: "xto.email"}
	assert.Equal(t, "abc123def456ghi7@xto.email", a.Address())
}

func newExpiry(store Store) ExpiryChecker {
	return NewExpiryChecker(store, discardLogger(), clock.NewFake(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)))
}

func TestNewExpiryChecker_NilClockDefaultsToSystem(t *testing.T) {
	e := NewExpiryChecker(&fakeStore{}, discardLogger(), nil)
	_, ok := e.clk.(clock.System)
	assert.True(t, ok)
}

func TestCheckOnce_DisablesExpired(t *testing.T) {
	store := &fakeStore{findExpired: []*Alias{
		{Subdomain: "a", Domain: "nix.contact"},
		{Subdomain: "b", Domain: "nix.contact"},
	}}
	e := newExpiry(store)

	require.NoError(t, e.CheckOnce(context.Background()))
	assert.Equal(t, []string{"a", "b"}, store.disabled)
}

func TestCheckOnce_FindError(t *testing.T) {
	e := newExpiry(&fakeStore{findExpiredErr: assertErr})

	assert.ErrorIs(t, e.CheckOnce(context.Background()), assertErr)
}

func TestCheckOnce_DisableErrorContinues(t *testing.T) {
	store := &fakeStore{
		findExpired: []*Alias{{Subdomain: "a", Domain: "nix.contact"}},
		disableErr:  assertErr,
	}
	e := newExpiry(store)

	// A disable failure is logged and swallowed, not returned.
	require.NoError(t, e.CheckOnce(context.Background()))
	assert.Equal(t, []string{"a"}, store.disabled)
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	e := newExpiry(&fakeStore{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.NoError(t, e.Run(ctx, time.Hour))
}

func TestRun_TicksThenStops(t *testing.T) {
	store := &fakeStore{findExpired: []*Alias{{Subdomain: "a", Domain: "nix.contact"}}}
	e := newExpiry(store)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	require.NoError(t, e.Run(ctx, time.Millisecond))
	assert.NotEmpty(t, store.disabled)
}

func TestRun_TickLogsCheckError(t *testing.T) {
	store := &fakeStore{findExpiredErr: assertErr}
	e := newExpiry(store)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// The per-tick error is logged inside Run, not returned.
	assert.NoError(t, e.Run(ctx, time.Millisecond))
}
