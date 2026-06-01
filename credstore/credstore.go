// Package credstore provides credential storage backends.
package credstore

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotFound is returned when a credential is not present in the backend.
var ErrNotFound = errors.New("credstore: credential not found")

// Backend is implemented by credential storage backends.
type Backend interface {
	Name() string
	Get(ctx context.Context, contextName string) (string, error)
	Put(ctx context.Context, contextName, password string) error
	Delete(ctx context.Context, contextName string) error
	Available() error
}

var knownBackends = []func() Backend{
	func() Backend { return &plainYamlBackend{} },
	func() Backend { return &keychainBackend{} },
	func() Backend { return &encryptedFileBackend{} },
	func() Backend { return &vaultBackend{} },
}

// New creates a Backend by name.
func New(name string) (Backend, error) {
	for _, ctor := range knownBackends {
		backend := ctor()
		if backend.Name() == name {
			return backend, nil
		}
	}
	return nil, fmt.Errorf("credstore: unknown backend %q", name)
}

// Available returns the usable backend names.
func Available() []string {
	names := make([]string, 0, len(knownBackends))
	for _, ctor := range knownBackends {
		backend := ctor()
		if backend.Available() == nil {
			names = append(names, backend.Name())
		}
	}
	return names
}
