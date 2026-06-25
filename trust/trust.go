// Package trust provides transport-neutral trust-on-first-use pin storage.
package trust

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/lockfile"
)

// Pin is one trust-on-first-use endpoint material record.
type Pin struct {
	Address     string
	Algorithm   string
	Fingerprint string
	Material    []byte
}

// Store stores TOFU pins at a TSV file path.
type Store struct {
	path string
}

// New creates a Store for the given TSV pin file path.
func New(path string) *Store {
	return &Store{path: path}
}

// PinChangedError reports a pinned endpoint presenting different material for the same algorithm.
type PinChangedError struct {
	Address             string
	Algorithm           string
	ExpectedFingerprint string
	ActualFingerprint   string
}

func (e *PinChangedError) Error() string {
	return fmt.Sprintf(
		"trust pin changed for %s (%s): expected %s, received %s",
		e.Address,
		e.Algorithm,
		e.ExpectedFingerprint,
		e.ActualFingerprint,
	)
}

// PinAlgorithmChangedError reports a known endpoint presenting an unpinned algorithm.
type PinAlgorithmChangedError struct {
	Address          string
	ActualAlgorithm  string
	PinnedAlgorithms []string
}

func (e *PinAlgorithmChangedError) Error() string {
	return fmt.Sprintf(
		"trust pin algorithm changed for %s: pinned algorithms %s, received %s; remove the endpoint pin manually before an authorized key rotation",
		e.Address,
		strings.Join(e.PinnedAlgorithms, ", "),
		e.ActualAlgorithm,
	)
}

type storedPin struct {
	Address     string
	Algorithm   string
	Fingerprint string
	Material    string
}

// VerifyOrPin verifies candidate against an existing pin or appends it on first use.
func (s *Store) VerifyOrPin(address string, candidate Pin, notify func(Pin)) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create trust directory", err)
	}
	lock := lockfile.New(s.path)
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	if err := securePinFile(s.path); err != nil {
		return err
	}
	pins, err := loadPins(s.path)
	if err != nil {
		return err
	}
	actual := candidate
	actual.Address = address
	addressKnown := false
	var sameAlgorithmPins []storedPin
	pinnedAlgorithms := make(map[string]bool)
	for _, existing := range pins {
		if existing.Address != address {
			continue
		}
		addressKnown = true
		pinnedAlgorithms[existing.Algorithm] = true
		if existing.Algorithm != candidate.Algorithm {
			continue
		}
		sameAlgorithmPins = append(sameAlgorithmPins, existing)
		decoded, decodeErr := base64.StdEncoding.DecodeString(existing.Material)
		if decodeErr != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to parse trust pin", decodeErr)
		}
		if bytes.Equal(decoded, candidate.Material) {
			return nil
		}
	}
	if len(sameAlgorithmPins) > 0 {
		existing := sameAlgorithmPins[0]
		return &PinChangedError{
			Address:             address,
			Algorithm:           candidate.Algorithm,
			ExpectedFingerprint: existing.Fingerprint,
			ActualFingerprint:   actual.Fingerprint,
		}
	}
	if addressKnown {
		algorithms := make([]string, 0, len(pinnedAlgorithms))
		for algorithm := range pinnedAlgorithms {
			algorithms = append(algorithms, algorithm)
		}
		sort.Strings(algorithms)
		return &PinAlgorithmChangedError{
			Address:          address,
			ActualAlgorithm:  candidate.Algorithm,
			PinnedAlgorithms: algorithms,
		}
	}
	if err := appendPin(s.path, actual); err != nil {
		return err
	}
	if notify != nil {
		notify(actual)
	}
	return nil
}

func loadPins(path string) ([]storedPin, error) {
	file, err := os.Open(path) //nolint:gosec // Configured trust-store path is inspected for symlinks and locked before this call.
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to open trust pins", err)
	}
	defer func() { _ = file.Close() }()

	var pins []storedPin
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "invalid trust pin record", nil)
		}
		pins = append(pins, storedPin{
			Address:     fields[0],
			Algorithm:   fields[1],
			Fingerprint: fields[2],
			Material:    fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read trust pins", err)
	}
	return pins, nil
}

func appendPin(path string, pin Pin) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // Configured trust-store path is locked and secured immediately after creation.
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open trust pins", err)
	}
	defer func() { _ = file.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure trust pins", err)
	}
	if err := setPinFileACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure trust pins", err)
	}
	if _, err := fmt.Fprintf(file, "%s\t%s\t%s\t%s\n", pin.Address, pin.Algorithm, pin.Fingerprint, base64.StdEncoding.EncodeToString(pin.Material)); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write trust pin", err)
	}
	return nil
}

func securePinFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect trust pins", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "trust pin path must be a regular file", nil)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure trust pins", err)
	}
	if err := setPinFileACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure trust pins", err)
	}
	return verifyPinFileSecurity(path)
}

// CheckPermissions validates an existing pin file without modifying it.
// A missing file is valid because TOFU has not initialized the store yet.
func CheckPermissions(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect trust pins", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, apperrors.New(apperrors.CodeLocalIOError, "trust pin path must be a regular file", nil)
	}
	if err := verifyPinFileSecurity(path); err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "trust pin permissions are insecure", err)
	}
	return true, nil
}
