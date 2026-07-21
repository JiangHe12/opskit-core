package ctx

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

type testContext struct {
	Base `yaml:",inline"`

	Backend string `yaml:"backend"`
	Region  string `yaml:"region,omitempty"`
}

var testStore = NewStore(func(item *testContext) *Base { return &item.Base })

type noBaseContext struct {
	Server              string `yaml:"server"`
	Username            string `yaml:"username"`
	Namespace           string `yaml:"namespace"`
	OtelEndpoint        string `yaml:"otelEndpoint,omitempty"`
	OtelRedactNamespace string `yaml:"otelRedactNamespace,omitempty"`
}

func configureTestStore(t *testing.T) {
	t.Helper()

	Configure(Options{APIVersion: "test.io/context/v1", ConfigDirName: ".opskit-test"})
	SetConfigPath("")

	t.Cleanup(func() {
		SetConfigPath("")
		Configure(Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
	})
}

func setTestHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestStoreLifecycleSetUseCurrentDelete(t *testing.T) {
	configureTestStore(t)
	home := setTestHome(t)

	input := testContext{
		Base: Base{
			Server:   "https://sentinel.example.test",
			Username: "alice",
			Env:      "prod",
			Roles:    map[string]string{"admin": "rw", "operator": "ro"},
		},
		Backend: "nacos",
		Region:  "cn-east-1",
	}
	if err := testStore.SetContext("prod", input); err != nil {
		t.Fatalf("SetContext() error = %v", err)
	}
	if err := testStore.UseContext("prod"); err != nil {
		t.Fatalf("UseContext() error = %v", err)
	}

	current, name, err := testStore.Current()
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if name != "prod" {
		t.Fatalf("Current() name = %q, want prod", name)
	}
	if current.Server != input.Server || current.Backend != input.Backend || current.Region != input.Region {
		t.Fatalf("Current() = %+v, want fields from %+v", current, input)
	}

	configPath := filepath.Join(home, ".opskit-test", "config.yaml")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("Stat(config.yaml) error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("config.yaml mode = %v, want 0600", got)
		}
	}

	if err := testStore.DeleteContext("prod"); err != nil {
		t.Fatalf("DeleteContext() error = %v", err)
	}
	cfg, err := testStore.Load()
	if err != nil {
		t.Fatalf("Load() after delete error = %v", err)
	}
	if _, ok := cfg.Contexts["prod"]; ok {
		t.Fatalf("deleted context still present: %+v", cfg.Contexts["prod"])
	}
	if cfg.CurrentContext != "" {
		t.Fatalf("current after delete = %q, want empty", cfg.CurrentContext)
	}
}

func TestStoreRejectsUnsupportedAPIVersion(t *testing.T) {
	configureTestStore(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("apiVersion: old\ncurrent-context: prod\ncontexts:\n  prod:\n    server: https://example.test\n    backend: nacos\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	SetConfigPath(path)

	if _, err := testStore.Load(); err == nil {
		t.Fatal("Load() error = nil, want unsupported apiVersion error")
	}
}

func TestStoreRejectsUnknownYAMLFields(t *testing.T) {
	configureTestStore(t)

	tests := []struct {
		name    string
		content string
	}{
		{
			name: "top level",
			content: `apiVersion: test.io/context/v1
current-context: prod
unexpectedRoot: true
contexts:
  prod:
    server: https://example.test
    backend: nacos
`,
		},
		{
			name: "context",
			content: `apiVersion: test.io/context/v1
current-context: prod
contexts:
  prod:
    server: https://example.test
    protectd: true
    backend: nacos
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			SetConfigPath(path)

			if _, err := testStore.Load(); err == nil {
				t.Fatal("Load() error = nil, want unknown field error")
			}
		})
	}
}

func TestStoreUpdateRejectsUnknownYAMLFieldsBeforeCallback(t *testing.T) {
	configureTestStore(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`apiVersion: test.io/context/v1
current-context: prod
contexts:
  prod:
    server: https://example.test
    protectd: true
    backend: nacos
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	SetConfigPath(path)

	called := false
	err := testStore.Update(func(_ *Config[testContext]) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Update() error = nil, want unknown field error")
	}
	if called {
		t.Fatal("Update() called callback for a context file with unknown fields")
	}
}

func TestStoreRoundTripKeepsFlatContextShape(t *testing.T) {
	configureTestStore(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`apiVersion: test.io/context/v1
current-context: prod
contexts:
  prod:
    server: https://sentinel.example.test
    username: alice
    password: secret
    env: prod
    protected: true
    ticketPattern: TICKET-[0-9]+
    ticketValidator: https://tickets.example.test/validate
    credentialBackend: vault
    roles:
      admin: rw
      operator: ro
    rolesSource: url
    rolesURL: https://roles.example.test/list
    allowInsecureRolesURL: true
    otlpEndpoint: https://otel.example.test
    otlpEndpointSource: config
    otlpMetricsEndpoint: https://metrics.example.test
    otlpMetricsSource: config
    otlpInsecure: true
    otlpRedact: false
    otlpRedactApp: demo
    auditMaxSize: 1048576
    auditEncryptKey: key-ref
    backupKeep: 42
    vaultAddr: https://vault.example.test
    vaultPath: secret/data/opskit
    vaultRoleID: role-id
    vaultNamespace: namespace-a
    backend: nacos
    region: cn-east-1
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	SetConfigPath(path)

	cfg, err := testStore.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	ctx := cfg.Contexts["prod"]
	if ctx.Server != "https://sentinel.example.test" || ctx.Backend != "nacos" || ctx.Region != "cn-east-1" {
		t.Fatalf("loaded context lost fields: %+v", ctx)
	}
	if len(ctx.Roles) != 2 || ctx.Roles["admin"] != "rw" || ctx.VaultAddr != "https://vault.example.test" || ctx.BackupKeep != 42 {
		t.Fatalf("loaded base fields mismatch: %+v", ctx)
	}

	if err := testStore.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(saved, &root); err != nil {
		t.Fatalf("Unmarshal(saved) error = %v", err)
	}
	prod := mappingValueForTest(mappingValueForTest(root.Content[0], "contexts"), "prod")
	if prod == nil {
		t.Fatal("saved YAML missing contexts.prod")
	}
	for _, key := range []string{"server", "roles", "otlpEndpoint", "vaultAddr", "backupKeep", "backend", "region"} {
		if mappingValueForTest(prod, key) == nil {
			t.Fatalf("saved contexts.prod missing flat key %q; YAML:\n%s", key, saved)
		}
	}
	if mappingValueForTest(prod, "base") != nil {
		t.Fatalf("saved contexts.prod contains unexpected base child; YAML:\n%s", saved)
	}
}

func TestStoreAppliesContextDefaults(t *testing.T) {
	configureTestStore(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("apiVersion: test.io/context/v1\ncurrent-context: prod\ncontexts:\n  prod:\n    server: https://example.test\n    backend: nacos\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	SetConfigPath(path)

	cfg, err := testStore.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	ctx := cfg.Contexts["prod"]
	if ctx.BackupKeep != 10 {
		t.Fatalf("BackupKeep default = %d, want 10", ctx.BackupKeep)
	}
	if ctx.OTLPEndpointSource != "auto" {
		t.Fatalf("OTLPEndpointSource default = %q, want auto", ctx.OTLPEndpointSource)
	}
	if ctx.OTLPMetricsSource != "auto" {
		t.Fatalf("OTLPMetricsSource default = %q, want auto", ctx.OTLPMetricsSource)
	}
	if !ctx.OTLPRedact {
		t.Fatal("OTLPRedact default = false, want true")
	}
}

func TestStoreWithoutBaseRoundTripDoesNotRequireBase(t *testing.T) {
	configureTestStore(t)
	store := NewStoreWithoutBase[noBaseContext]()

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`apiVersion: test.io/context/v1
current-context: prod
contexts:
  prod:
    server: http://prod:8848
    username: nacos
    namespace: public
    otelEndpoint: http://collector:4318
    otelRedactNamespace: public-
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	SetConfigPath(path)

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	ctx := cfg.Contexts["prod"]
	if ctx.Server != "http://prod:8848" || ctx.Username != "nacos" || ctx.Namespace != "public" || ctx.OtelEndpoint != "http://collector:4318" || ctx.OtelRedactNamespace != "public-" {
		t.Fatalf("loaded context = %+v", ctx)
	}

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(saved, &root); err != nil {
		t.Fatalf("Unmarshal(saved) error = %v", err)
	}
	prod := mappingValueForTest(mappingValueForTest(root.Content[0], "contexts"), "prod")
	for _, key := range []string{"server", "username", "namespace", "otelEndpoint", "otelRedactNamespace"} {
		if mappingValueForTest(prod, key) == nil {
			t.Fatalf("saved contexts.prod missing key %q; YAML:\n%s", key, saved)
		}
	}
	for _, key := range []string{"backupKeep", "otlpEndpoint", "otlpRedact", "base"} {
		if mappingValueForTest(prod, key) != nil {
			t.Fatalf("saved contexts.prod has unexpected key %q; YAML:\n%s", key, saved)
		}
	}
}

func TestBaseResolvePasswordContextPlain(t *testing.T) {
	base := Base{Password: "plain-secret"}

	password, err := base.ResolvePasswordContext(context.Background(), "prod")
	if err != nil {
		t.Fatalf("ResolvePasswordContext() error = %v", err)
	}
	if password != "plain-secret" {
		t.Fatalf("ResolvePasswordContext() = %q, want plain-secret", password)
	}
}

func mappingValueForTest(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
