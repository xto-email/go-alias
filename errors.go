package alias

import errs "github.com/gomatic/go-error"

// Sentinel errors this package emits, matchable with errors.Is. The Const
// mechanism is owned by gomatic/go-error. Keep sorted alphabetically.
const (
	ErrAliasDuplicate      errs.Const = "alias already exists"
	ErrAliasLimitReached   errs.Const = "maximum alias limit reached"
	ErrAliasNotFound       errs.Const = "alias not found"
	ErrBurnerNoExpiration  errs.Const = "burner domain aliases must have an expiration"
	ErrCheckAliasCount     errs.Const = "checking alias count"
	ErrCheckDomainSecurity errs.Const = "checking domain security"
	ErrCountAliases        errs.Const = "counting aliases"
	ErrDeleteAlias         errs.Const = "deleting alias"
	ErrDeleteUserAliases   errs.Const = "deleting user aliases"
	ErrDisableAlias        errs.Const = "disabling alias"
	ErrDomainNotAllowed    errs.Const = "domain must be one of: xto.email, nix.contact, 83g.one"
	ErrDomainSecurity      errs.Const = "domain does not meet security requirements"
	ErrEmptySecretKey      errs.Const = "empty secret key"
	ErrFindExpired         errs.Const = "finding expired aliases"
	ErrGenerateAlias       errs.Const = "generating alias"
	ErrInsertAlias         errs.Const = "inserting alias"
	ErrInvalidAlias        errs.Const = "invalid alias"
	ErrInvalidDomain       errs.Const = "invalid domain: must contain a dot"
	ErrListAliases         errs.Const = "listing aliases"
	ErrQueryAlias          errs.Const = "querying alias"
	ErrScanAlias           errs.Const = "scanning alias"
	ErrScanExpired         errs.Const = "scanning expired alias"
	ErrSenderDomainNoDot   errs.Const = "sender_domain must contain a dot"
	ErrStoreAlias          errs.Const = "storing alias"
	ErrSubdomainFormat     errs.Const = "subdomain must be 16 lowercase alphanumeric characters"
	ErrXtoEmailExpiration  errs.Const = "xto.email aliases must not have an expiration"
)
