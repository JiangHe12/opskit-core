package credstore

import "github.com/JiangHe12/opskit-core/apperrors"

// IsPlaintextBackend reports whether the named backend persists credentials in
// plaintext. An empty name resolves to the default plain-yaml backend.
func IsPlaintextBackend(name string) bool {
	return name == "" || name == "plain-yaml"
}

// RequireSecureBackend rejects storing a secret under a plaintext backend. The
// hasSecret argument reports whether any credential value will be persisted;
// when it is false the check is a no-op so non-credential context updates are
// unaffected. Callers collapse their own credential fields into hasSecret.
func RequireSecureBackend(backend string, hasSecret bool) error {
	if hasSecret && IsPlaintextBackend(backend) {
		return apperrors.New(apperrors.CodeUsageError, "credentials must use a non-plain credential backend", nil)
	}
	return nil
}
