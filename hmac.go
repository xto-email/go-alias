package alias

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"time"
)

const (
	subdomainLength  = 16
	validationWindow = 3 // days
)

// Subdomain is the 16-character lowercase base32 alias label — the part of an
// alias address before the "@" — deterministically derived from the sender
// domain and the HMAC secret key.
type Subdomain string

// SenderDomain is the DNS domain of the message sender that an alias is
// cryptographically bound to (e.g. "newsletter.com").
type SenderDomain string

// SenderAddress is a full sender email address (e.g. "news@example.com"); the
// sender domain an alias is validated against is extracted from it.
type SenderAddress string

// Generate produces a deterministic 16-character lowercase alphanumeric
// subdomain from a sender domain and secret key. The subdomain is derived
// from HMAC-SHA256(key, domain|date) encoded as lowercase base32.
func Generate(senderDomain SenderDomain, secretKey []byte) (string, error) {
	return generateWithDate(senderDomain, secretKey, time.Now().UTC())
}

// generateWithDate is the internal implementation that accepts an explicit
// date for testing and validation window checking.
func generateWithDate(senderDomain SenderDomain, secretKey []byte, date time.Time) (string, error) {
	if len(secretKey) == 0 {
		return "", ErrEmptySecretKey
	}

	domain := SenderDomain(strings.ToLower(strings.TrimSpace(string(senderDomain))))
	if !containsDot(domain) {
		return "", ErrInvalidDomain
	}

	datePrefix := date.Format("2006-01-02")
	data := string(domain) + "|" + datePrefix

	mac := hmac.New(sha256.New, secretKey)
	_, _ = mac.Write([]byte(data)) // hash.Hash.Write never returns an error
	hash := mac.Sum(nil)

	// Take first 10 bytes, base32-encode, lowercase, truncate to 16 chars
	encoded := base32.StdEncoding.EncodeToString(hash[:10])
	subdomain := strings.ToLower(encoded)[:subdomainLength]

	return subdomain, nil
}

// Validate checks if an alias subdomain is valid for the given sender email
// address under a single secret key. It is a convenience wrapper over
// ValidateMulti for callers that have not rotated.
//
// SECURITY: Uses constant-time comparison to prevent timing attacks.
func Validate(subdomain Subdomain, senderFrom SenderAddress, secretKey []byte) (bool, error) {
	return ValidateMulti(subdomain, senderFrom, [][]byte{secretKey})
}

// ValidateMulti checks the alias against every key in the ring, within the
// 3-day validation window (clock skew + delivery delay). The ring carries the
// current key plus recently-rotated previous keys, so rotating HMAC_SECRET_KEY
// never invalidates a live alias and a leaked key can be retired by dropping it
// from the ring (FR-038). A single-key ring is identical to the old behavior.
func ValidateMulti(subdomain Subdomain, senderFrom SenderAddress, secretKeys [][]byte) (bool, error) {
	if subdomain == "" || senderFrom == "" || len(secretKeys) == 0 {
		return false, nil
	}
	senderDomain, ok := domainFromSender(senderFrom)
	if !ok {
		return false, nil
	}
	return matchesAnyKey(subdomain, senderDomain, secretKeys, time.Now().UTC()), nil
}

// matchesAnyKey reports whether subdomain validates under any non-empty key in
// the ring (within the date window).
func matchesAnyKey(subdomain Subdomain, senderDomain SenderDomain, secretKeys [][]byte, now time.Time) bool {
	for _, key := range secretKeys {
		if len(key) > 0 && matchesWithinWindow(subdomain, senderDomain, key, now) {
			return true
		}
	}
	return false
}

// domainFromSender extracts the domain from a sender email address. The second
// return is false when the address has no "@".
func domainFromSender(senderFrom SenderAddress) (SenderDomain, bool) {
	parts := strings.Split(string(senderFrom), "@")
	if len(parts) < 2 {
		return "", false
	}
	return SenderDomain(parts[len(parts)-1]), true
}

// matchesWithinWindow reports whether subdomain equals the alias derived for
// senderDomain on any day in the validation window ending at now. Comparison is
// constant-time to prevent a timing side-channel.
func matchesWithinWindow(subdomain Subdomain, senderDomain SenderDomain, secretKey []byte, now time.Time) bool {
	for i := 0; i <= validationWindow; i++ {
		date := now.AddDate(0, 0, -i)
		expected, err := generateWithDate(senderDomain, secretKey, date)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(subdomain), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}
