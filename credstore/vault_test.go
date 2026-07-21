package credstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestVaultBackendTokenRoundTrip(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "root-token")
	var stored string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root-token" {
			t.Fatalf("X-Vault-Token = %q, want root-token", r.Header.Get("X-Vault-Token"))
		}
		if r.URL.Path != "/v1/secret/data/service/prod" {
			t.Fatalf("path = %q, want /v1/secret/data/service/prod", r.URL.Path)
		}
		switch r.Method {
		case http.MethodPost:
			var payload struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			stored = payload.Data["password"]
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if stored == "" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]string{"password": stored}},
			})
		case http.MethodDelete:
			stored = ""
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	backend := NewVault(VaultConfig{Addr: server.URL, Path: "service/prod"}).(*vaultBackend)
	backend.client = server.Client()
	if err := backend.Put(context.Background(), "prod", "nacos-pass"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := backend.Get(context.Background(), "prod")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "nacos-pass" {
		t.Fatalf("Get() = %q, want nacos-pass", got)
	}
	if err := backend.Delete(context.Background(), "prod"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := backend.Get(context.Background(), "prod"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestVaultBackendAppRoleLoginCachesToken(t *testing.T) {
	t.Setenv("VAULT_SECRET_ID", "secret-id")
	loginCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			loginCount++
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["role_id"] != "role-id" || payload["secret_id"] != "secret-id" {
				t.Fatalf("login payload = %#v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]string{"client_token": "login-token"},
			})
		case "/v1/secret/data/service/prod":
			if r.Header.Get("X-Vault-Token") != "login-token" {
				t.Fatalf("X-Vault-Token = %q, want login-token", r.Header.Get("X-Vault-Token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]string{"password": "stored"}},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	backend := NewVault(VaultConfig{Addr: server.URL, Path: "service/prod", RoleID: "role-id"}).(*vaultBackend)
	backend.client = server.Client()
	for range 2 {
		if _, err := backend.Get(context.Background(), "prod"); err != nil {
			t.Fatalf("Get() error = %v", err)
		}
	}
	if loginCount != 1 {
		t.Fatalf("login count = %d, want 1", loginCount)
	}
}

func TestVaultBackendNamespaceHeader(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "root-token")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Namespace") != "team-a" {
			t.Fatalf("X-Vault-Namespace = %q, want team-a", r.Header.Get("X-Vault-Namespace"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]string{"password": "stored"}},
		})
	}))
	defer server.Close()

	backend := NewVault(VaultConfig{Addr: server.URL, Path: "service/prod", Namespace: "team-a"}).(*vaultBackend)
	backend.client = server.Client()
	if _, err := backend.Get(context.Background(), "prod"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestVaultBackendAvailableRequiresAuthEnv(t *testing.T) {
	backend := NewVault(VaultConfig{Addr: "https://vault.example", Path: "service/prod"})
	if err := backend.Available(); err == nil {
		t.Fatal("Available() error = nil, want error")
	}
	t.Setenv("VAULT_TOKEN", "root-token")
	if err := backend.Available(); err != nil {
		t.Fatalf("Available() error = %v", err)
	}
}

func TestVaultBackendRejectsNonHTTPSAndAmbiguousAddresses(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "root-token")
	for _, addr := range []string{
		"http://vault.example",
		"vault.example",
		"https:///missing-host",
		"https://user@vault.example",
		"https://vault.example?namespace=team-a",
		"https://vault.example#fragment",
	} {
		t.Run(addr, func(t *testing.T) {
			backend := NewVault(VaultConfig{Addr: addr, Path: "service/prod"})
			if err := backend.Available(); err == nil {
				t.Fatal("Available() error = nil, want secure-address validation error")
			} else if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeUsageError {
				t.Fatalf("Available() code = %s, want %s", appErr.Code, apperrors.CodeUsageError)
			}
		})
	}
}
