package credstore

import (
	"context"
	"errors"
	"testing"
)

func TestPlainYamlBackend(t *testing.T) {
	backend, err := New("plain-yaml")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if backend.Name() != "plain-yaml" {
		t.Fatalf("Name() = %q", backend.Name())
	}
	if err := backend.Available(); err != nil {
		t.Fatalf("Available() error = %v", err)
	}
	if _, err := backend.Get(context.Background(), "dev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestReferenceRoundTrip(t *testing.T) {
	ref := ParseRef(EncodeRef("keychain"))
	if !ref.IsRef || ref.BackendName != "keychain" {
		t.Fatalf("ParseRef() = %+v", ref)
	}
}

func TestAvailableIncludesPlainYaml(t *testing.T) {
	names := Available()
	for _, name := range names {
		if name == "plain-yaml" {
			return
		}
	}
	t.Fatalf("Available() = %v, want plain-yaml", names)
}
