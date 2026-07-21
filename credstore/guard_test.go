package credstore

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestIsPlaintextBackend(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"", true},
		{"plain-yaml", true},
		{"keychain", false},
		{"encrypted-file", false},
		{"vault", false},
	}
	for _, c := range cases {
		if got := IsPlaintextBackend(c.name); got != c.want {
			t.Errorf("IsPlaintextBackend(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRequireSecureBackend(t *testing.T) {
	cases := []struct {
		name      string
		backend   string
		hasSecret bool
		wantErr   bool
	}{
		{"plaintext with secret rejected", "plain-yaml", true, true},
		{"empty backend with secret rejected", "", true, true},
		{"plaintext without secret allowed", "plain-yaml", false, false},
		{"secure backend with secret allowed", "keychain", true, false},
		{"secure backend without secret allowed", "encrypted-file", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := RequireSecureBackend(c.backend, c.hasSecret)
			if c.wantErr {
				if err == nil {
					t.Fatalf("RequireSecureBackend(%q, %v) = nil, want error", c.backend, c.hasSecret)
				}
				appErr := apperrors.AsAppError(err)
				if appErr.Code != apperrors.CodeUsageError {
					t.Errorf("code = %s, want %s", appErr.Code, apperrors.CodeUsageError)
				}
				if appErr.Message != "credentials must use a non-plain credential backend" {
					t.Errorf("message = %q, want guard message", appErr.Message)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequireSecureBackend(%q, %v) = %v, want nil", c.backend, c.hasSecret, err)
			}
		})
	}
}
