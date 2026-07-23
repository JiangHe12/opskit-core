// Package trust provides transport-neutral trust-on-first-use pin storage.
package trust

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/securefile"
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
	if err := securefile.EnsureParent(s.path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create trust directory", err)
	}
	lock := lockfile.New(s.path)
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

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
	}
	if len(sameAlgorithmPins) > 0 {
		existing := sameAlgorithmPins[0]
		expectedMaterial, decodeErr := base64.StdEncoding.DecodeString(existing.Material)
		if decodeErr != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to parse trust pin", decodeErr)
		}
		if existing.Fingerprint == candidate.Fingerprint && bytes.Equal(expectedMaterial, candidate.Material) {
			return nil
		}
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
	data, err := securefile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to open trust pins", err)
	}

	var pins []storedPin
	scanner := bufio.NewScanner(bytes.NewReader(data))
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
	if err := validateDuplicatePins(pins); err != nil {
		return nil, err
	}
	return pins, nil
}

func validateDuplicatePins(pins []storedPin) error {
	type pinKey struct {
		address   string
		algorithm string
	}
	seen := make(map[pinKey]storedPin, len(pins))
	for _, pin := range pins {
		key := pinKey{address: pin.Address, algorithm: pin.Algorithm}
		existing, duplicate := seen[key]
		if !duplicate {
			seen[key] = pin
			continue
		}
		expectedMaterial, err := base64.StdEncoding.DecodeString(existing.Material)
		if err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to parse trust pin", err)
		}
		actualMaterial, err := base64.StdEncoding.DecodeString(pin.Material)
		if err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to parse trust pin", err)
		}
		if existing.Fingerprint != pin.Fingerprint || !bytes.Equal(expectedMaterial, actualMaterial) {
			return apperrors.New(apperrors.CodeLocalIOError, "conflicting duplicate trust pin records", nil)
		}
	}
	return nil
}

func appendPin(path string, pin Pin) error {
	data, err := securefile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read trust pins", err)
	}
	var next bytes.Buffer
	next.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		next.WriteByte('\n')
	}
	_, _ = fmt.Fprintf(
		&next,
		"%s\t%s\t%s\t%s\n",
		pin.Address,
		pin.Algorithm,
		pin.Fingerprint,
		base64.StdEncoding.EncodeToString(pin.Material),
	)
	if err := securefile.WriteFile(path, next.Bytes()); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write trust pin", err)
	}
	return nil
}

// CheckPermissions validates an existing pin file without modifying it.
// A missing file is valid because TOFU has not initialized the store yet.
func CheckPermissions(path string) (bool, error) {
	exists, err := securefile.CheckFile(path)
	if err != nil {
		return exists, apperrors.New(apperrors.CodeLocalIOError, "trust pin permissions are insecure", err)
	}
	return exists, nil
}
