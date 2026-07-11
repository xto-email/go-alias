package alias

import (
	"testing"
	"time"
)

func TestAliasIsActive(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		expires *time.Time
		name    string
		enabled bool
		want    bool
	}{
		{name: "disabled never resolves", enabled: false, expires: nil, want: false},
		{name: "disabled with future expiry still inactive", enabled: false, expires: &future, want: false},
		{name: "enabled, no expiry", enabled: true, expires: nil, want: true},
		{name: "enabled, future expiry", enabled: true, expires: &future, want: true},
		{name: "enabled, past expiry fails closed", enabled: true, expires: &past, want: false},
		{name: "enabled, expiry exactly now fails closed", enabled: true, expires: &now, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Alias{Enabled: tc.enabled, ExpiresAt: tc.expires}
			if got := a.IsActive(now); got != tc.want {
				t.Fatalf("IsActive = %v, want %v", got, tc.want)
			}
		})
	}
}
