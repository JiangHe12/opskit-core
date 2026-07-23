//go:build !windows

package ctx

import (
	"os"
	"testing"
)

func secureTestRoot(*testing.T, string) {}

func TestStoreUpdateRejectsInsecureExistingFileModeBeforeCallback(t *testing.T) {
	configureTestStore(t)

	path := privateTestPath(t, "config.yaml")
	content := []byte("apiVersion: test.io/context/v1\ncurrent-context: \"\"\ncontexts: {}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	SetConfigPath(path)

	called := false
	err := testStore.Update(func(_ *Config[testContext]) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Update() error = nil, want insecure mode error")
	}
	if called {
		t.Fatal("Update() called callback before rejecting insecure file mode")
	}
}
