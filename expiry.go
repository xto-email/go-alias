package alias

import (
	"context"
	"log/slog"
	"time"

	"github.com/gomatic/go-clock"
)

type ExpiryChecker struct {
	store  Store
	logger *slog.Logger
	clk    clock.Clock
}

// NewExpiryChecker builds the sweeper. A nil clock uses the system clock.
func NewExpiryChecker(store Store, logger *slog.Logger, clk clock.Clock) ExpiryChecker {
	if clk == nil {
		clk = clock.System{}
	}
	return ExpiryChecker{store: store, logger: logger, clk: clk}
}

// CheckOnce runs a single expiry sweep, disabling aliases whose expiry is
// before the injected clock's current time. Exposed for tests.
func (e ExpiryChecker) CheckOnce(ctx context.Context) error {
	return e.checkExpired(ctx)
}

// Run periodically checks for expired burner aliases and disables them.
// It runs every interval until the context is cancelled.
func (e ExpiryChecker) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := e.checkExpired(ctx); err != nil {
				e.logger.Error("expiry check failed", "error", err)
			}
		}
	}
}

func (e ExpiryChecker) checkExpired(ctx context.Context) error {
	expired, err := e.store.FindExpiredAsOf(ctx, e.clk.Now())
	if err != nil {
		return err
	}

	for _, a := range expired {
		if err := e.store.Disable(ctx, a.Subdomain); err != nil {
			e.logger.Error(
				"failed to disable expired alias",
				"subdomain", a.Subdomain,
				"expires_at", a.ExpiresAt,
				"error", err,
			)
			continue
		}
		e.logger.Info(
			"expired alias disabled",
			"subdomain", a.Subdomain,
			"domain", a.Domain,
		)
	}

	if len(expired) > 0 {
		e.logger.Info("expiry check complete", "disabled_count", len(expired))
	}
	return nil
}
