package alias

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerate_KnownAnswer pins the alias-derivation contract to an
// independently computed vector (HMAC-SHA256("test-secret-key",
// "example.com|2026-01-01") → first 10 bytes → base32 → lowercase → 16 chars,
// computed with `openssl dgst -sha256 -hmac`). The derivation defines every
// alias that exists, so changing it silently breaks revocation and resolution
// for all of them: this test must never be "fixed" by editing want — a failure
// means the derivation regressed.
func TestGenerate_KnownAnswer(t *testing.T) {
	const want = "wpebsnnzm4uogwaq"
	got, err := generateWithDate("example.com", []byte("test-secret-key"),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, want, got, "alias derivation changed — this breaks every existing alias")
}

func TestGenerate_Deterministic(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	sub1, err := generateWithDate("gmail.com", key, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	sub2, err := generateWithDate("gmail.com", key, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	assert.Equal(t, sub1, sub2, "same inputs must produce same subdomain")
}

func TestGenerate_SubdomainFormat(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sub, err := Generate("newsletter.com", key)
	require.NoError(t, err)
	assert.Len(t, sub, subdomainLength)
	assert.Regexp(t, `^[a-z0-9]+$`, sub)
}

func TestGenerate_DifferentDomainsDifferentSubdomains(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	date := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)

	sub1, _ := generateWithDate("gmail.com", key, date)
	sub2, _ := generateWithDate("outlook.com", key, date)

	assert.NotEqual(t, sub1, sub2)
}

func TestGenerate_DifferentKeysDifferentSubdomains(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)
	date := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)

	sub1, _ := generateWithDate("gmail.com", key1, date)
	sub2, _ := generateWithDate("gmail.com", key2, date)

	assert.NotEqual(t, sub1, sub2)
}

func TestGenerate_NormalizesCase(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	date := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)

	sub1, _ := generateWithDate("Gmail.COM", key, date)
	sub2, _ := generateWithDate("gmail.com", key, date)

	assert.Equal(t, sub1, sub2, "domain should be case-insensitive")
}

func TestGenerate_EmptyKey(t *testing.T) {
	_, err := Generate("gmail.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty secret key")

	_, err = Generate("gmail.com", []byte{})
	assert.Error(t, err)
}

func TestGenerate_InvalidDomain(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	_, err := Generate("nodot", key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must contain a dot")
}

func TestValidate_MatchesGenerated(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sub, err := Generate("newsletter.com", key)
	require.NoError(t, err)

	valid, err := Validate(Subdomain(sub), "hello@newsletter.com", key)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateMulti_AcceptsAnyKeyInRing(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	_, _ = rand.Read(keyA)
	_, _ = rand.Read(keyB)

	sub, err := Generate("rotation.com", keyA)
	require.NoError(t, err)
	const from = "hello@rotation.com"

	// During rotation the ring holds the new primary (keyB) plus the previous
	// key (keyA); an alias minted under keyA must still validate.
	ok, err := ValidateMulti(Subdomain(sub), from, [][]byte{keyB, keyA})
	require.NoError(t, err)
	assert.True(t, ok, "alias from keyA must validate against a ring containing keyA")

	// Once keyA is retired from the ring, the alias no longer validates.
	ok, _ = ValidateMulti(Subdomain(sub), from, [][]byte{keyB})
	assert.False(t, ok, "alias from keyA must not validate against a ring without keyA")

	// An empty ring validates nothing.
	ok, _ = ValidateMulti(Subdomain(sub), from, nil)
	assert.False(t, ok)
}

func TestValidate_RejectsWrongSender(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sub, _ := Generate("newsletter.com", key)

	valid, _ := Validate(Subdomain(sub), "attacker@spammer.com", key)
	assert.False(t, valid)
}

func TestValidate_RejectsWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)

	sub, _ := Generate("newsletter.com", key1)

	valid, _ := Validate(Subdomain(sub), "hello@newsletter.com", key2)
	assert.False(t, valid)
}

func TestValidate_ValidationWindow(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	// Generate alias for 3 days ago — should still validate
	threeDaysAgo := time.Now().UTC().AddDate(0, 0, -3)
	sub, _ := generateWithDate("gmail.com", key, threeDaysAgo)

	valid, _ := Validate(Subdomain(sub), "user@gmail.com", key)
	assert.True(t, valid, "alias from 3 days ago should still validate")

	// Generate alias for 4 days ago — should fail
	fourDaysAgo := time.Now().UTC().AddDate(0, 0, -4)
	sub2, _ := generateWithDate("gmail.com", key, fourDaysAgo)

	valid2, _ := Validate(Subdomain(sub2), "user@gmail.com", key)
	assert.False(t, valid2, "alias from 4 days ago should be expired")
}

func TestValidate_EmptyInputs(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	valid, _ := Validate("", "user@gmail.com", key)
	assert.False(t, valid)

	valid, _ = Validate("abc123", "", key)
	assert.False(t, valid)

	valid, _ = Validate("abc123", "user@gmail.com", nil)
	assert.False(t, valid)
}

func TestValidate_SenderWithoutAt(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	valid, _ := Validate("abc123def456ghi7", "nodomain", key)
	assert.False(t, valid)
}

func TestValidate_SenderDomainWithoutDot(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	// The sender has an "@" so domain extraction succeeds, but the extracted
	// domain has no dot, so every windowed derivation errors and is skipped.
	valid, err := Validate("abc123def456ghi7", "user@nodot", key)
	require.NoError(t, err)
	assert.False(t, valid)
}
