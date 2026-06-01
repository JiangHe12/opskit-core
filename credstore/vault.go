package credstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

const vaultBackendName = "vault"

// VaultConfig configures the Vault credential backend.
type VaultConfig struct {
	Addr      string
	Path      string
	RoleID    string
	Namespace string
}

type vaultBackend struct {
	cfg    VaultConfig
	client *http.Client
	mu     sync.Mutex
	token  string
}

// NewVault creates a Vault credential backend for a specific context.
func NewVault(cfg VaultConfig) Backend {
	return &vaultBackend{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

func (v *vaultBackend) Name() string { return vaultBackendName }

func (v *vaultBackend) Available() error {
	if err := v.validateConfig(false); err != nil {
		return err
	}
	if os.Getenv("VAULT_SECRET_ID") != "" {
		if v.cfg.RoleID == "" {
			return errors.New("vault: vaultRoleID is required for AppRole auth")
		}
		return nil
	}
	if os.Getenv("VAULT_TOKEN") != "" {
		return nil
	}
	return errors.New("vault: VAULT_SECRET_ID or VAULT_TOKEN must be set")
}

func (v *vaultBackend) Get(ctx context.Context, _ string) (string, error) {
	if err := v.validateConfig(true); err != nil {
		return "", err
	}
	token, err := v.authToken(ctx)
	if err != nil {
		return "", err
	}
	req, err := v.newRequest(ctx, http.MethodGet, v.secretURL(), token, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "vault credential read failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to read Vault response", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", vaultHTTPError("vault credential read failed", resp.StatusCode, body)
	}
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to parse Vault secret response", err)
	}
	password := out.Data.Data["password"]
	if password == "" {
		return "", ErrNotFound
	}
	return password, nil
}

func (v *vaultBackend) Put(ctx context.Context, _ string, password string) error {
	if err := v.validateConfig(true); err != nil {
		return err
	}
	token, err := v.authToken(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{"data": map[string]string{"password": password}}
	body, err := json.Marshal(payload)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to encode Vault secret", err)
	}
	req, err := v.newRequest(ctx, http.MethodPost, v.secretURL(), token, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "vault credential write failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to read Vault response", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vaultHTTPError("vault credential write failed", resp.StatusCode, respBody)
	}
	return nil
}

func (v *vaultBackend) Delete(ctx context.Context, _ string) error {
	if err := v.validateConfig(true); err != nil {
		return err
	}
	token, err := v.authToken(ctx)
	if err != nil {
		return err
	}
	req, err := v.newRequest(ctx, http.MethodDelete, v.secretURL(), token, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "vault credential delete failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to read Vault response", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vaultHTTPError("vault credential delete failed", resp.StatusCode, body)
	}
	return nil
}

func (v *vaultBackend) validateConfig(requireAddr bool) error {
	if requireAddr && strings.TrimSpace(v.cfg.Addr) == "" {
		return apperrors.New(apperrors.CodeCredentialStoreError, "vault credential backend requires vaultAddr", nil)
	}
	if strings.TrimSpace(v.cfg.Path) == "" {
		return apperrors.New(apperrors.CodeCredentialStoreError, "vault credential backend requires vaultPath", nil)
	}
	return nil
}

func (v *vaultBackend) authToken(ctx context.Context) (string, error) {
	if secretID := os.Getenv("VAULT_SECRET_ID"); secretID != "" {
		if strings.TrimSpace(v.cfg.RoleID) == "" {
			return "", apperrors.New(apperrors.CodeCredentialStoreError, "vaultRoleID is required when VAULT_SECRET_ID is set", nil)
		}
		return v.loginAppRole(ctx, secretID)
	}
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}
	return "", apperrors.New(apperrors.CodeCredentialStoreError, "vault credential backend requires VAULT_SECRET_ID or VAULT_TOKEN", nil)
}

func (v *vaultBackend) loginAppRole(ctx context.Context, secretID string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" {
		return v.token, nil
	}
	payload := map[string]string{"role_id": v.cfg.RoleID, "secret_id": secretID}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to encode Vault AppRole login", err)
	}
	req, err := v.newRequest(ctx, http.MethodPost, v.apiURL("auth/approle/login"), "", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "vault AppRole login failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to read Vault response", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", vaultHTTPError("vault AppRole login failed", resp.StatusCode, respBody)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to parse Vault AppRole login response", err)
	}
	if out.Auth.ClientToken == "" {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "vault AppRole login response missing client token", nil)
	}
	v.token = out.Auth.ClientToken
	return v.token, nil
}

func (v *vaultBackend) newRequest(ctx context.Context, method, rawURL, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to build Vault request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	return req, nil
}

func (v *vaultBackend) secretURL() string {
	return v.apiURL("secret/data/" + strings.Trim(strings.TrimSpace(v.cfg.Path), "/"))
}

func (v *vaultBackend) apiURL(path string) string {
	base := strings.TrimRight(v.cfg.Addr, "/")
	escaped := strings.Split(path, "/")
	for i, part := range escaped {
		escaped[i] = url.PathEscape(part)
	}
	return base + "/v1/" + strings.Join(escaped, "/")
}

func vaultHTTPError(message string, status int, body []byte) error {
	text := strings.TrimSpace(string(body))
	if text == "" {
		text = http.StatusText(status)
	}
	return apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("%s: HTTP %d: %s", message, status, text), nil)
}
