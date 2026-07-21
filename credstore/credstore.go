// Package credstore provides credential storage backends.
package credstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// ErrNotFound is returned when a credential is not present in the backend.
var ErrNotFound = errors.New("credstore: credential not found")

// Backend is implemented by credential storage backends. Context cancellation
// is backend-specific. In particular, OS keychain Put and Delete honor a
// cancellation observed before the mutation starts; once the OS call starts,
// they wait for its definite result because the keychain API cannot cancel a
// mutation transactionally.
type Backend interface {
	Name() string
	Get(ctx context.Context, contextName string) (string, error)
	Put(ctx context.Context, contextName, password string) error
	Delete(ctx context.Context, contextName string) error
	Available() error
}

var backendFactories = map[string]func() Backend{
	"plain-yaml":     func() Backend { return &plainYamlBackend{} },
	"keychain":       func() Backend { return &keychainBackend{} },
	"encrypted-file": func() Backend { return &encryptedFileBackend{} },
	vaultBackendName: func() Backend { return &vaultBackend{} },
}

var backendOrder = []string{
	"plain-yaml",
	"keychain",
	"encrypted-file",
	vaultBackendName,
}

// Register adds or replaces a credential backend factory.
func Register(name string, factory func() Backend) {
	backendFactories[name] = factory
	for _, existing := range backendOrder {
		if existing == name {
			return
		}
	}
	backendOrder = append(backendOrder, name)
}

// New creates a Backend by name.
func New(name string) (Backend, error) {
	if factory, ok := backendFactories[name]; ok {
		return factory(), nil
	}
	return nil, fmt.Errorf("credstore: unknown backend %q", name)
}

// Available returns the usable backend names.
func Available() []string {
	names := make([]string, 0, len(backendFactories))
	seen := make(map[string]bool)
	for _, name := range backendOrder {
		factory, ok := backendFactories[name]
		if !ok || factory == nil || seen[name] {
			continue
		}
		seen[name] = true
		backend := factory()
		if backend.Available() == nil {
			names = append(names, backend.Name())
		}
	}
	var extra []string
	for name, factory := range backendFactories {
		if seen[name] || factory == nil {
			continue
		}
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		backend := backendFactories[name]()
		if backend.Available() == nil {
			names = append(names, backend.Name())
		}
	}
	return names
}
