package alias

import (
	"context"
	"log/slog"
	"time"

	"github.com/gomatic/go-domainsec"
)

// domainReChecker re-validates whether a sender domain still meets the security
// floor. *domainsec.Service satisfies it via CheckDomain.
type domainReChecker interface {
	CheckDomain(ctx context.Context, domain string) (*domainsec.DomainSecurityReport, error)
}

// DegradationChecker enforces the security invariant over time: an alias is bound
// to a sender domain that passed DKIM+DMARC at creation, but a domain can later
// drop below the floor. This sweep re-checks each active alias's sender domain
// and disables aliases whose domain no longer allows alias creation.
type DegradationChecker struct {
	store   Store
	domains domainReChecker
	logger  *slog.Logger
}

// NewDegradationChecker builds the sweeper.
func NewDegradationChecker(store Store, domains domainReChecker, logger *slog.Logger) DegradationChecker {
	return DegradationChecker{store: store, domains: domains, logger: logger}
}

// CheckOnce runs a single degradation sweep. Exposed for tests and on-demand use.
func (d DegradationChecker) CheckOnce(ctx context.Context) error {
	active, err := d.store.ListActive(ctx)
	if err != nil {
		return err
	}
	for _, a := range active {
		d.evaluate(ctx, *a)
	}
	return nil
}

// Run sweeps every interval until the context is cancelled.
func (d DegradationChecker) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := d.CheckOnce(ctx); err != nil {
				d.logger.Error("degradation check failed", "error", err)
			}
		}
	}
}

// evaluate disables one alias if its sender domain has dropped below the floor;
// transient check errors are logged and leave the alias untouched (fail open on
// a lookup blip rather than disabling on a false negative).
func (d DegradationChecker) evaluate(ctx context.Context, a Alias) {
	report, err := d.domains.CheckDomain(ctx, a.SenderDomain)
	if err != nil {
		d.logger.Error("degradation re-check failed", "sender", a.SenderDomain, "error", err)
		return
	}
	if report.MeetsSecurityFloor() {
		return
	}
	if err := d.store.Disable(ctx, a.Subdomain); err != nil {
		d.logger.Error("failed to disable degraded alias", "subdomain", a.Subdomain, "error", err)
		return
	}
	d.logger.Warn("disabled alias: sender domain dropped below security floor",
		"subdomain", a.Subdomain, "sender", a.SenderDomain)
}
