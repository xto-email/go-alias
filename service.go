// Package alias derives, persists, and validates sender-locked email aliases.
//
// An alias is a deterministic HMAC derivation cryptographically bound to a
// single sender domain: the same (secret, domain, label) inputs always yield
// the same alias, and the binding cannot be transferred to another sender.
// Creation is refused unless the sender domain passes the domainsec security
// gate (DKIM + DMARC at p=quarantine or p=reject); disabled or expired aliases
// resolve to NXDOMAIN at the DNS layer before any message reaches SMTP.
package alias

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gomatic/go-clock"
	"github.com/gomatic/go-domainsec"
)

// domainChecker is the subset of *domainsec.Service the alias Service depends
// on. It exists so the security-gate logic is unit-testable with a fake,
// leaving the concrete domainsec.Service as the only production adapter.
type domainChecker interface {
	CheckDomain(ctx context.Context, domain string) (*domainsec.DomainSecurityReport, error)
}

// Service derives, persists, and validates sender-locked aliases. It is an
// immutable value holding its injected collaborators (a store, a domain
// checker, a clock, a logger, and the secret key ring).
type Service struct {
	store      Store
	domainSvc  domainChecker
	clk        clock.Clock
	logger     *slog.Logger
	secretKeys [][]byte
}

// NewService builds the alias service. domainSvc is the security gate seam
// (production passes the domainsec.Service value; tests inject a fake).
// secretKeys is the alias HMAC key ring: secretKeys[0] is the current key
// (used to mint new aliases) and any further entries are recently-rotated
// previous keys still honored at validation, so rotating HMAC_SECRET_KEY never
// invalidates a live alias. A nil clock uses the system clock.
func NewService(
	store Store,
	domainSvc domainChecker,
	secretKeys [][]byte,
	logger *slog.Logger,
	clk clock.Clock,
) Service {
	if clk == nil {
		clk = clock.System{}
	}
	return Service{
		store:      store,
		domainSvc:  domainSvc,
		secretKeys: secretKeys,
		logger:     logger,
		clk:        clk,
	}
}

// primaryKey is the current key used to mint new aliases, or nil when no key is
// configured (Generate then fails closed with ErrEmptySecretKey).
func (s Service) primaryKey() []byte {
	if len(s.secretKeys) == 0 {
		return nil
	}
	return s.secretKeys[0]
}

func (s Service) burnerExpiry() time.Time {
	return s.clk.Now().Add(7 * 24 * time.Hour)
}

func (s Service) Generate(ctx context.Context, senderDomain, userID, domain string) (*Alias, error) {
	if err := s.assertDomainSecure(ctx, senderDomain); err != nil {
		return nil, err
	}

	a, err := s.buildAlias(senderDomain, userID, domain)
	if err != nil {
		return nil, err
	}

	if err := s.store.Create(ctx, *a); err != nil {
		return nil, ErrStoreAlias.With(err)
	}

	s.logger.Info(
		"alias created",
		"subdomain", a.Subdomain,
		"domain", domain,
		"sender_domain", senderDomain,
		"user_id", userID,
	)
	return a, nil
}

// assertDomainSecure runs the non-negotiable DKIM+DMARC gate: alias creation is
// refused unless the sender domain passes. The returned error keeps the leading
// word "domain" that internal/api/handlers classifies on.
func (s Service) assertDomainSecure(ctx context.Context, senderDomain string) error {
	report, err := s.domainSvc.CheckDomain(ctx, senderDomain)
	if err != nil {
		return ErrCheckDomainSecurity.With(err)
	}
	if !report.MeetsSecurityFloor() {
		return ErrDomainSecurity.With(
			nil,
			fmt.Sprintf("sender=%s DKIM=%v DMARC=%s", senderDomain, report.HasDKIM, report.DMARCPolicy),
		)
	}
	return nil
}

// buildAlias derives the subdomain, assembles the Alias, applies the burner
// expiry policy, and self-validates it.
func (s Service) buildAlias(senderDomain, userID, domain string) (*Alias, error) {
	subdomain, err := Generate(SenderDomain(senderDomain), s.primaryKey())
	if err != nil {
		return nil, ErrGenerateAlias.With(err)
	}

	a := &Alias{
		Subdomain:    subdomain,
		Domain:       domain,
		SenderDomain: senderDomain,
		UserID:       userID,
		Enabled:      true,
	}
	if domain != permanentDomain {
		exp := s.burnerExpiry()
		a.ExpiresAt = &exp
	}

	if err := a.Validate(); err != nil {
		return nil, ErrInvalidAlias.With(err)
	}
	return a, nil
}

func (s Service) ValidateHMAC(subdomain Subdomain, senderFrom SenderAddress) (bool, error) {
	return ValidateMulti(subdomain, senderFrom, s.secretKeys)
}

func (s Service) GetBySubdomain(ctx context.Context, subdomain string) (*Alias, error) {
	return s.store.GetBySubdomain(ctx, subdomain)
}

// GetForUser returns the alias only when userID owns it. A missing alias, an
// alias owned by another user, and a lookup failure are all surfaced as
// ErrAliasNotFound, so a caller can neither read nor confirm the existence of an
// alias it does not own. This is the owner-scoped read the public API must use;
// the unscoped GetBySubdomain above serves the system DNS/SMTP resolution path,
// which has no authenticated user.
func (s Service) GetForUser(ctx context.Context, userID, subdomain string) (*Alias, error) {
	a, err := s.store.GetBySubdomain(ctx, subdomain)
	if err != nil {
		return nil, err
	}
	if a.UserID != userID {
		return nil, ErrAliasNotFound
	}
	return a, nil
}

// ActiveBySubdomain returns the alias for subdomain only when it currently
// resolves as live: it exists, is enabled, and has not expired as of the service
// clock. A missing, disabled, or expired alias yields ErrAliasNotFound, so the
// DNS and SMTP read paths fail closed on expiry without waiting for the
// asynchronous sweep. This is the single resolution seam both read paths share;
// GetBySubdomain stays for owner-facing reads that must see an inactive alias.
func (s Service) ActiveBySubdomain(ctx context.Context, subdomain string) (*Alias, error) {
	a, err := s.store.GetBySubdomain(ctx, subdomain)
	if err != nil {
		return nil, err
	}
	if !a.IsActive(s.clk.Now()) {
		return nil, ErrAliasNotFound
	}
	return a, nil
}

// DisableForUser disables the alias only when userID owns it; a non-owner or
// missing alias is reported as ErrAliasNotFound, preventing one user from
// disabling (and thereby revoking mail for) another user's alias.
func (s Service) DisableForUser(ctx context.Context, userID, subdomain string) error {
	a, err := s.store.GetBySubdomain(ctx, subdomain)
	if err != nil {
		return err
	}
	if a.UserID != userID {
		return ErrAliasNotFound
	}
	return s.Disable(ctx, subdomain)
}

func (s Service) List(ctx context.Context, userID string) ([]*Alias, error) {
	return s.store.ListByUser(ctx, userID)
}

type WithSecurity struct {
	Alias          *Alias
	DomainSecurity *domainsec.DomainSecurityReport
}

func (s Service) ListWithSecurity(ctx context.Context, userID string) ([]*WithSecurity, error) {
	aliases, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, ErrListAliases.With(err)
	}

	results := make([]*WithSecurity, 0, len(aliases))
	for _, a := range aliases {
		report, err := s.domainSvc.CheckDomain(ctx, a.SenderDomain)
		if err != nil {
			// A check failure must not fail the whole listing, but it also must
			// not be silent: log it so a transient resolver error is
			// distinguishable from a genuine security downgrade.
			s.logger.Warn("domain security check failed", "sender_domain", a.SenderDomain, "error", err)
		}
		results = append(results, &WithSecurity{
			Alias:          a,
			DomainSecurity: report,
		})
	}
	return results, nil
}

func (s Service) Disable(ctx context.Context, subdomain string) error {
	if err := s.store.Disable(ctx, subdomain); err != nil {
		return ErrDisableAlias.With(err)
	}
	s.logger.Info("alias disabled", "subdomain", subdomain)
	return nil
}
