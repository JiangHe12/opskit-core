package trust

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/securefile"
)

func TestVerifyOrPinTruthTableByAddress(t *testing.T) {
	path := trustTestPath(t)
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

	for _, candidate := range []Pin{
		testPin("ssh-ed25519", "SHA256:changed", "original-key"),
		testPin("ssh-ed25519", "SHA256:original", "changed-key"),
	} {
		err := store.VerifyOrPin(address, candidate, nil)
		var changed *PinChangedError
		if !errors.As(err, &changed) {
			t.Fatalf("partially matching same-algorithm error = %T %v", err, err)
		}
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

func TestVerifyOrPinNotifiesWhenPinCommittedBeforePostCommitError(t *testing.T) {
	path := trustTestPath(t)
	store := New(path)
	injected := errors.New("injected post-commit failure")
	store.writeFile = func(path string, data []byte) (securefile.WriteResult, error) {
		if err := securefile.WriteFile(path, data); err != nil {
			return securefile.WriteResult{State: securefile.WriteCommitNotCommitted}, err
		}
		return securefile.WriteResult{
			State: securefile.WriteCommitCommittedPostCommitError,
		}, injected
	}
	address := "server.example:22"
	candidate := testPin("ssh-ed25519", "SHA256:committed", "committed-key")
	var notifications []Pin
	err := store.VerifyOrPin(address, candidate, func(pin Pin) {
		notifications = append(notifications, pin)
	})
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("VerifyOrPin() error = %v, want injected post-commit failure", err)
	}
	if len(notifications) != 1 || notifications[0].Address != address {
		t.Fatalf("TOFU notifications = %#v, want committed pin", notifications)
	}

	if err := New(path).VerifyOrPin(address, candidate, func(Pin) {
		t.Fatal("existing committed pin notified twice")
	}); err != nil {
		t.Fatalf("VerifyOrPin(existing) error = %v", err)
	}
}

func TestVerifyOrPinDoesNotNotifyWhenPinWasNotCommitted(t *testing.T) {
	path := trustTestPath(t)
	store := New(path)
	injected := errors.New("injected pre-commit failure")
	store.writeFile = func(string, []byte) (securefile.WriteResult, error) {
		return securefile.WriteResult{State: securefile.WriteCommitNotCommitted}, injected
	}
	notifications := 0
	err := store.VerifyOrPin(
		"server.example:22",
		testPin("ssh-ed25519", "SHA256:not-committed", "not-committed-key"),
		func(Pin) { notifications++ },
	)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("VerifyOrPin() error = %v, want injected pre-commit failure", err)
	}
	if notifications != 0 {
		t.Fatalf("TOFU notifications = %d, want 0", notifications)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("trust pin file error = %v, want not exist", statErr)
	}
}

func TestVerifyOrPinRejectsConflictingLegacyDuplicates(t *testing.T) {
	address := "server.example:22"
	tests := []struct {
		name   string
		first  Pin
		second Pin
	}{
		{
			name:   "different fingerprint",
			first:  testPin("ssh-ed25519", "SHA256:first", "same-key"),
			second: testPin("ssh-ed25519", "SHA256:second", "same-key"),
		},
		{
			name:   "different material",
			first:  testPin("ssh-ed25519", "SHA256:same", "first-key"),
			second: testPin("ssh-ed25519", "SHA256:same", "second-key"),
		},
	}
	for _, tt := range tests {
		for candidateIndex, candidate := range []Pin{tt.first, tt.second} {
			t.Run(fmt.Sprintf("%s/candidate-%d", tt.name, candidateIndex+1), func(t *testing.T) {
				path := trustTestPath(t)
				original := []byte(strings.Join([]string{
					storedPinLine(address, tt.first),
					storedPinLine(address, tt.second),
					"",
				}, "\n"))
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}

				notifications := 0
				err := New(path).VerifyOrPin(address, candidate, func(Pin) {
					notifications++
				})
				if err == nil {
					t.Fatal("VerifyOrPin() error = nil, want conflicting duplicate rejection")
				}
				if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeLocalIOError {
					t.Fatalf("error code = %s, want %s", appErr.Code, apperrors.CodeLocalIOError)
				}
				if !strings.Contains(err.Error(), "conflicting duplicate trust pin records") {
					t.Fatalf("error = %v", err)
				}
				if notifications != 0 {
					t.Fatalf("notifications = %d, want 0", notifications)
				}
				after, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("ReadFile() error = %v", readErr)
				}
				if !bytes.Equal(after, original) {
					t.Fatalf("trust store changed: got %q, want %q", after, original)
				}
			})
		}
	}
}

func TestVerifyOrPinAcceptsIdenticalLegacyDuplicatesWithoutRewrite(t *testing.T) {
	path := trustTestPath(t)
	address := "server.example:22"
	candidate := testPin("ssh-ed25519", "SHA256:same", "same-key")
	line := storedPinLine(address, candidate)
	original := []byte(line + "\n" + line + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	notifications := 0
	if err := New(path).VerifyOrPin(address, candidate, func(Pin) {
		notifications++
	}); err != nil {
		t.Fatalf("VerifyOrPin() error = %v", err)
	}
	if notifications != 0 {
		t.Fatalf("notifications = %d, want 0", notifications)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("trust store changed: got %q, want %q", after, original)
	}
}

func TestVerifyOrPinReadsLegacyTSVAndSkipsComments(t *testing.T) {
	path := trustTestPath(t)
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
	path := trustTestPath(t)
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
	path := trustTestPath(t)
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
	secureTrustTestRoot(t, dir)
	target := filepath.Join(dir, "target.tsv")
	path := filepath.Join(dir, "pins.tsv")
	const original = "referent-must-not-change"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := New(path).VerifyOrPin("server.example:22", testPin("ssh-ed25519", "SHA256:actual", "actual-key"), nil)
	if err == nil {
		t.Fatal("VerifyOrPin() error = nil, want symlink rejection")
	}
	if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeLocalIOError {
		t.Fatalf("error code = %s, want %s", appErr.Code, apperrors.CodeLocalIOError)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatalf("Lstat() error = %v", statErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("pin path mode = %v, want symlink unchanged", info.Mode())
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile(target) error = %v", readErr)
	}
	if string(data) != original {
		t.Fatalf("target = %q, want %q", data, original)
	}
}

func TestCheckPermissions(t *testing.T) {
	path := trustTestPath(t)
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
	path := trustTestPath(t)
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

func storedPinLine(address string, pin Pin) string {
	return strings.Join([]string{
		address,
		pin.Algorithm,
		pin.Fingerprint,
		base64.StdEncoding.EncodeToString(pin.Material),
	}, "\t")
}

func trustTestPath(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	secureTrustTestRoot(t, root)
	return filepath.Join(root, "pins.tsv")
}
