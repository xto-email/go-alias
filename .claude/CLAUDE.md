# go-alias

The alias domain service of the xto-email ecosystem: alias minting (HMAC-derived subdomains), validation (subdomain format, allowed domains, sender-domain, permanent-vs-burner expiry invariants), expiry sweeping, degradation checks against domain security, and the pgx-backed store. Extracted from `xto`'s `internal/alias` when the repo split into `xtod`/`xtoctl` (see `_projects/specs/repo-split/`).

- Library repo (`library.go` marker); flat single-package layout at the root; deps: pgx (store), `gomatic/go-clock` (injectable time), `gomatic/go-domainsec` (security gate, `MeetsSecurityFloor`), `gomatic/go-error` (sentinels), testify for tests.
- Gate: shared Makefile from `nicerobot/tools.repository` — gofumpt, vet, staticcheck, golangci-lint, govulncheck, gocognit ≤ 7, 100% coverage. Never edit the distributed `Makefile`/`.golangci.yaml`/`.github` in-tree.
- Public docs live in `docs.go-alias`; the README is exactly badges + the docs link.
