package alias

import (
	"context"
	"time"
)

const MaxAliasesPerUser = 100

type Store interface {
	Create(ctx context.Context, alias Alias) error
	GetBySubdomain(ctx context.Context, subdomain string) (*Alias, error)
	ListByUser(ctx context.Context, userID string) ([]*Alias, error)
	ListActive(ctx context.Context) ([]*Alias, error)
	Disable(ctx context.Context, subdomain string) error
	Delete(ctx context.Context, subdomain string) error
	CountActiveByUser(ctx context.Context, userID string) (int, error)
	DeleteByUser(ctx context.Context, userID string) error
	FindExpired(ctx context.Context) ([]*Alias, error)
	// FindExpiredAsOf returns active aliases whose expiry is before cutoff.
	// It lets the sweeper use an injected clock instead of the DB's now().
	FindExpiredAsOf(ctx context.Context, cutoff time.Time) ([]*Alias, error)
}
