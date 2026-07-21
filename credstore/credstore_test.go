package credstore

import (
	"context"
	"errors"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/zalando/go-keyring"
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

func TestRegisterAddsBackend(t *testing.T) {
	Register("test-registry", func() Backend { return testBackend{name: "test-registry"} })

	backend, err := New("test-registry")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if backend.Name() != "test-registry" {
		t.Fatalf("Name() = %q, want test-registry", backend.Name())
	}
}

func TestRegisterOverridesBackend(t *testing.T) {
	Register("plain-yaml", func() Backend { return testBackend{name: "plain-yaml", marker: "override"} })
	t.Cleanup(func() { Register("plain-yaml", func() Backend { return &plainYamlBackend{} }) })

	backend, err := New("plain-yaml")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := backend.Get(context.Background(), "ctx")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "override" {
		t.Fatalf("Get() = %q, want override", got)
	}
}

func TestKeychainAccountPrefixCanBeConfiguredEmpty(t *testing.T) {
	origGet := keychainGet
	origOptions := options
	defer func() {
		keychainGet = origGet
		options = origOptions
	}()

	var gotService, gotAccount string
	keychainGet = func(service, account string) (string, error) {
		gotService = service
		gotAccount = account
		return "stored", nil
	}

	Configure(Options{KeychainService: "nacos-cli", KeychainAccountPrefix: ""})
	password, err := (&keychainBackend{}).Get(context.Background(), "prod")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if password != "stored" {
		t.Fatalf("password = %q, want stored", password)
	}
	if gotService != "nacos-cli" || gotAccount != "prod" {
		t.Fatalf("keychain lookup = service %q account %q, want nacos-cli/prod", gotService, gotAccount)
	}
}

func TestKeychainAccountDefaultIsBareContextName(t *testing.T) {
	origGet := keychainGet
	origOptions := options
	defer func() {
		keychainGet = origGet
		options = origOptions
	}()

	var gotService, gotAccount string
	keychainGet = func(service, account string) (string, error) {
		gotService = service
		gotAccount = account
		return "stored", nil
	}

	password, err := (&keychainBackend{}).Get(context.Background(), "prod")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if password != "stored" {
		t.Fatalf("password = %q, want stored", password)
	}
	if gotService != "opskit" || gotAccount != "prod" {
		t.Fatalf("keychain lookup = service %q account %q, want opskit/prod", gotService, gotAccount)
	}
}

func TestVaultPreciseErrorMapping(t *testing.T) {
	_, err := NewVault(VaultConfig{Path: "secret"}).Get(context.Background(), "ctx")
	if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeUsageError {
		t.Fatalf("missing addr code = %s, want %s", appErr.Code, apperrors.CodeUsageError)
	}

	t.Setenv("VAULT_SECRET_ID", "secret-id")
	_, err = NewVault(VaultConfig{Addr: "https://127.0.0.1", Path: "secret"}).Get(context.Background(), "ctx")
	if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeUsageError {
		t.Fatalf("missing role id code = %s, want %s", appErr.Code, apperrors.CodeUsageError)
	}
}

func TestKeychainGetMapsNotFound(t *testing.T) {
	origGet := keychainGet
	defer func() { keychainGet = origGet }()
	keychainGet = func(string, string) (string, error) {
		return "", keyring.ErrNotFound
	}
	if _, err := (&keychainBackend{}).Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

type testBackend struct {
	name   string
	marker string
}

func (t testBackend) Name() string { return t.name }

func (t testBackend) Get(context.Context, string) (string, error) { return t.marker, nil }

func (t testBackend) Put(context.Context, string, string) error { return nil }

func (t testBackend) Delete(context.Context, string) error { return nil }

func (t testBackend) Available() error { return nil }
