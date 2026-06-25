package trust

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func TestVerifyOrPinTruthTableByAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.tsv")
	store := New(path)
	address := "server.example:22"
	original := testPin("ssh-ed25519", "SHA256:original", "original-key")

	var pins []Pin
	if err := store.VerifyOrPin(address, original, func(pin Pin) {
		pins = append(pins, pin)
	}); err != nil {
		t.Fatalf("unknown address VerifyOrPin() error = %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("TOFU notifications = %d, want 1", len(pins))
	}
	if pins[0].Address != address {
		t.Fatalf("notified address = %q, want %q", pins[0].Address, address)
	}

	if err := store.VerifyOrPin(address, original, nil); err != nil {
		t.Fatalf("same material VerifyOrPin() error = %v", err)
	}

	err := store.VerifyOrPin(address, testPin("ssh-ed25519", "SHA256:changed", "changed-key"), nil)
	var changed *PinChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("different same-algorithm error = %T %v", err, err)
	}
	if changed.ExpectedFingerprint != original.Fingerprint || changed.ActualFingerprint != "SHA256:changed" {
		t.Fatalf("changed error = %#v", changed)
	}

	err = store.VerifyOrPin(address, testPin("rsa-sha2-512", "SHA256:rsa", "rsa-key"), nil)
	var changedAlgorithm *PinAlgorithmChangedError
	if !errors.As(err, &changedAlgorithm) {
		t.Fatalf("new algorithm error = %T %v", err, err)
	}
	if changedAlgorithm.ActualAlgorithm != "rsa-sha2-512" {
		t.Fatalf("ActualAlgorithm = %q", changedAlgorithm.ActualAlgorithm)
	}
	if len(changedAlgorithm.PinnedAlgorithms) != 1 || changedAlgorithm.PinnedAlgorithms[0] != original.Algorithm {
		t.Fatalf("PinnedAlgorithms = %#v", changedAlgorithm.PinnedAlgorithms)
	}

	stored, err := loadPins(path)
	if err != nil {
		t.Fatalf("loadPins() error = %v", err)
	}
	if len(stored) != 1 || stored[0].Algorithm != original.Algorithm {
		t.Fatalf("stored pins = %#v, want only original pin", stored)
	}
}

func TestVerifyOrPinReadsLegacyTSVAndSkipsComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.tsv")
	material := []byte("legacy-material")
	content := strings.Join([]string{
		"# existing pins",
		"",
		"server.example:443\ttls-spki-sha256\tsha256/legacy\t" + base64.StdEncoding.EncodeToString(material),
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err := New(path).VerifyOrPin("server.example:443", Pin{
		Algorithm:   "tls-spki-sha256",
		Fingerprint: "sha256/legacy",
		Material:    material,
	}, nil)
	if err != nil {
		t.Fatalf("VerifyOrPin() legacy TSV error = %v", err)
	}
}

func TestVerifyOrPinMalformedRecordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.tsv")
	if err := os.WriteFile(path, []byte("server.example:22\tssh-ed25519\tSHA256:missing-material\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err := New(path).VerifyOrPin("server.example:22", testPin("ssh-ed25519", "SHA256:actual", "actual-key"), nil)
	if err == nil {
		t.Fatal("VerifyOrPin() error = nil, want malformed record error")
	}
	if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeLocalIOError {
		t.Fatalf("error code = %s", appErr.Code)
	}
}

func TestVerifyOrPinMalformedBase64ForMatchingAlgorithmFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.tsv")
	if err := os.WriteFile(path, []byte("server.example:22\tssh-ed25519\tSHA256:bad\t%%%not-base64%%%\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err := New(path).VerifyOrPin("server.example:22", testPin("ssh-ed25519", "SHA256:actual", "actual-key"), nil)
	if err == nil {
		t.Fatal("VerifyOrPin() error = nil, want malformed material error")
	}
	if !strings.Contains(err.Error(), "failed to parse trust pin") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyOrPinRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges not guaranteed in local test runs")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.tsv")
	path := filepath.Join(dir, "pins.tsv")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := New(path).VerifyOrPin("server.example:22", testPin("ssh-ed25519", "SHA256:actual", "actual-key"), nil)
	if err == nil {
		t.Fatal("VerifyOrPin() error = nil, want symlink rejection")
	}
	if !strings.Contains(err.Error(), "trust pin path must be a regular file") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.tsv")
	exists, err := CheckPermissions(path)
	if err != nil {
		t.Fatalf("CheckPermissions() missing error = %v", err)
	}
	if exists {
		t.Fatal("CheckPermissions() missing exists = true")
	}

	if err := New(path).VerifyOrPin("server.example:22", testPin("ssh-ed25519", "SHA256:actual", "actual-key"), nil); err != nil {
		t.Fatalf("VerifyOrPin() error = %v", err)
	}
	exists, err = CheckPermissions(path)
	if err != nil {
		t.Fatalf("CheckPermissions() existing error = %v", err)
	}
	if !exists {
		t.Fatal("CheckPermissions() existing exists = false")
	}
}

func TestConcurrentVerifyOrPinUsesLockfile(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "30s")
	path := filepath.Join(t.TempDir(), "pins.tsv")
	store := New(path)
	address := "server.example:22"
	candidate := testPin("ssh-ed25519", "SHA256:actual", "actual-key")

	const workers = 2
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	notifications := make(chan Pin, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.VerifyOrPin(address, candidate, func(pin Pin) {
				notifications <- pin
			})
		}()
	}
	wg.Wait()
	close(errs)
	close(notifications)

	for err := range errs {
		if err != nil {
			t.Fatalf("VerifyOrPin() concurrent error = %v", err)
		}
	}
	if got := len(notifications); got != 1 {
		t.Fatalf("notifications = %d, want 1", got)
	}
	stored, err := loadPins(path)
	if err != nil {
		t.Fatalf("loadPins() error = %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored pins = %d, want 1: %#v", len(stored), stored)
	}
}

func testPin(algorithm, fingerprint, material string) Pin {
	return Pin{
		Algorithm:   algorithm,
		Fingerprint: fingerprint,
		Material:    []byte(material),
	}
}
