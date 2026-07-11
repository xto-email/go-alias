package alias

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gomatic/go-domainsec"
)

// fakeReChecker returns a scripted report (or error) per sender domain.
type fakeReChecker struct {
	reports map[string]*domainsec.DomainSecurityReport
	err     error
}

func (f fakeReChecker) CheckDomain(_ context.Context, domain string) (*domainsec.DomainSecurityReport, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.reports[domain], nil
}

func newDegradationChecker(store Store, rc domainReChecker) DegradationChecker {
	return NewDegradationChecker(store, rc, slog.New(slog.DiscardHandler))
}

func TestDegradationDisablesDroppedDomain(t *testing.T) {
	store := &fakeStore{listActive: []*Alias{
		{Subdomain: "secure0000000000", SenderDomain: "good.example"},
		{Subdomain: "dropped000000000", SenderDomain: "bad.example"},
	}}
	rc := fakeReChecker{reports: map[string]*domainsec.DomainSecurityReport{
		"good.example": secureReport(),
		"bad.example":  insecureReport(),
	}}

	if err := newDegradationChecker(store, rc).CheckOnce(context.Background()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if len(store.disabled) != 1 || store.disabled[0] != "dropped000000000" {
		t.Fatalf("disabled = %v, want only the degraded alias", store.disabled)
	}
}

func TestDegradationListError(t *testing.T) {
	store := &fakeStore{listActiveErr: assertErr}
	if err := newDegradationChecker(store, fakeReChecker{}).CheckOnce(context.Background()); !errors.Is(
		err,
		assertErr,
	) {
		t.Fatalf("err = %v, want assertErr", err)
	}
}

func TestDegradationRecheckErrorLeavesAliasActive(t *testing.T) {
	store := &fakeStore{listActive: []*Alias{{Subdomain: "x000000000000000", SenderDomain: "blip.example"}}}
	if err := newDegradationChecker(store, fakeReChecker{err: assertErr}).CheckOnce(context.Background()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if len(store.disabled) != 0 {
		t.Fatalf("a transient re-check error must not disable; disabled = %v", store.disabled)
	}
}

func TestDegradationDisableErrorIsLogged(t *testing.T) {
	store := &fakeStore{
		listActive: []*Alias{{Subdomain: "y000000000000000", SenderDomain: "bad.example"}},
		disableErr: assertErr,
	}
	rc := fakeReChecker{reports: map[string]*domainsec.DomainSecurityReport{"bad.example": insecureReport()}}
	// CheckOnce swallows a per-alias Disable error (logged) and still returns nil.
	if err := newDegradationChecker(store, rc).CheckOnce(context.Background()); err != nil {
		t.Fatalf("CheckOnce must not propagate a per-alias disable error, got %v", err)
	}
}

func TestDegradationRunStopsOnContextCancel(t *testing.T) {
	d := newDegradationChecker(&fakeStore{}, fakeReChecker{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Run(ctx, time.Hour); err != nil {
		t.Fatalf("Run on cancelled context = %v, want nil", err)
	}
}

func TestDegradationRunTicksThenStops(t *testing.T) {
	store := &fakeStore{
		listActive: []*Alias{{Subdomain: "z000000000000000", SenderDomain: "bad.example"}},
	}
	rc := fakeReChecker{reports: map[string]*domainsec.DomainSecurityReport{"bad.example": insecureReport()}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := newDegradationChecker(store, rc).Run(ctx, time.Millisecond); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(store.disabled) == 0 {
		t.Fatal("a tick must have run the sweep and disabled the degraded alias")
	}
}

func TestDegradationRunTickLogsError(t *testing.T) {
	// A per-tick sweep error (here, ListActive failing) is logged inside Run, not
	// returned; Run still exits cleanly when the context expires.
	store := &fakeStore{listActiveErr: assertErr}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := newDegradationChecker(store, fakeReChecker{}).Run(ctx, time.Millisecond); err != nil {
		t.Fatalf("Run must not propagate a per-tick error, got %v", err)
	}
}
