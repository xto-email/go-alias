package alias

import (
	"regexp"
	"time"
)

// permanentDomain is the one alias domain whose aliases never expire; the
// burner domains require an expiry.
const (
	permanentDomain  = "xto.email"
	burnerNixContact = "nix.contact"
	burner83gOne     = "83g.one"
)

var (
	subdomainPattern = regexp.MustCompile(`^[a-z0-9]{16}$`)
	allowedDomains   = map[string]bool{
		permanentDomain:  true,
		burnerNixContact: true,
		burner83gOne:     true,
	}
)

type Alias struct {
	CreatedAt    time.Time  `json:"created_at"            db:"created_at"`
	DisabledAt   *time.Time `json:"disabled_at,omitempty" db:"disabled_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"  db:"expires_at"`
	Subdomain    string     `json:"subdomain"             db:"subdomain"`
	Domain       string     `json:"domain"                db:"domain"`
	SenderDomain string     `json:"sender_domain"         db:"sender_domain"`
	UserID       string     `json:"user_id"               db:"user_id"`
	// Enabled is the stored on/off switch (the wire/DB name stays "active";
	// see IsActive for the time-aware liveness check).
	Enabled bool `json:"active"                db:"active"`
}

// Validate checks the alias's structural and expiry invariants, returning the
// first sentinel that fails. The checks are expressed as a slice of predicates
// so each branch is independently testable and complexity stays low.
func (a Alias) Validate() error {
	checks := []func() error{
		a.checkSubdomain,
		a.checkDomain,
		a.checkSenderDomain,
		a.checkExpiry,
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (a Alias) checkSubdomain() error {
	if !subdomainPattern.MatchString(a.Subdomain) {
		return ErrSubdomainFormat
	}
	return nil
}

func (a Alias) checkDomain() error {
	if !allowedDomains[a.Domain] {
		return ErrDomainNotAllowed
	}
	return nil
}

func (a Alias) checkSenderDomain() error {
	if !containsDot(SenderDomain(a.SenderDomain)) {
		return ErrSenderDomainNoDot
	}
	return nil
}

func (a Alias) checkExpiry() error {
	if a.Domain == permanentDomain && a.ExpiresAt != nil {
		return ErrXtoEmailExpiration
	}
	if a.Domain != permanentDomain && a.ExpiresAt == nil {
		return ErrBurnerNoExpiration
	}
	return nil
}

func (a Alias) Address() string {
	return a.Subdomain + "@" + a.Domain
}

// IsActive reports whether the alias resolves as live at now: it must be enabled
// and, if it carries an expiry, that expiry must still be in the future. Folding
// expiry into the resolution decision makes an expired alias fail closed
// immediately at the DNS/SMTP read boundary, rather than resolving as active
// until the asynchronous expiry sweep flips its stored active flag.
func (a Alias) IsActive(now time.Time) bool {
	if !a.Enabled {
		return false
	}
	return a.ExpiresAt == nil || now.Before(*a.ExpiresAt)
}

// containsDot reports whether the sender domain contains at least one dot —
// the minimal structural check for a plausible DNS domain.
func containsDot(s SenderDomain) bool {
	for _, c := range string(s) {
		if c == '.' {
			return true
		}
	}
	return false
}
