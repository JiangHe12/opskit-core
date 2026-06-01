package ctx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"
	"github.com/JiangHe12/opskit-core/lockfile"
)

// Base contains common context fields shared by governed CLI tools.
type Base struct {
	Server                string            `yaml:"server"`
	Username              string            `yaml:"username,omitempty"`
	Password              string            `yaml:"password,omitempty"`
	Env                   string            `yaml:"env,omitempty"`
	Protected             bool              `yaml:"protected,omitempty"`
	TicketPattern         string            `yaml:"ticketPattern,omitempty"`
	TicketValidator       string            `yaml:"ticketValidator,omitempty"`
	CredentialBackend     string            `yaml:"credentialBackend,omitempty"`
	Roles                 map[string]string `yaml:"roles,omitempty"`
	RolesSource           string            `yaml:"rolesSource,omitempty"`
	RolesURL              string            `yaml:"rolesURL,omitempty"`
	AllowInsecureRolesURL bool              `yaml:"allowInsecureRolesURL,omitempty"`
	OTLPEndpoint          string            `yaml:"otlpEndpoint,omitempty"`
	OTLPEndpointSource    string            `yaml:"otlpEndpointSource,omitempty"`
	OTLPMetricsEndpoint   string            `yaml:"otlpMetricsEndpoint,omitempty"`
	OTLPMetricsSource     string            `yaml:"otlpMetricsSource,omitempty"`
	OTLPInsecure          bool              `yaml:"otlpInsecure,omitempty"`
	OTLPRedact            bool              `yaml:"otlpRedact"`
	OTLPRedactApp         string            `yaml:"otlpRedactApp,omitempty"`
	AuditMaxSize          int64             `yaml:"auditMaxSize,omitempty"`
	AuditEncryptKey       string            `yaml:"auditEncryptKey,omitempty"`
	BackupKeep            int               `yaml:"backupKeep"`
	VaultAddr             string            `yaml:"vaultAddr,omitempty"`
	VaultPath             string            `yaml:"vaultPath,omitempty"`
	VaultRoleID           string            `yaml:"vaultRoleID,omitempty"`
	VaultNamespace        string            `yaml:"vaultNamespace,omitempty"`
}

// ResolvePasswordContext resolves literal or credstore referenced passwords.
func (b Base) ResolvePasswordContext(ctx context.Context, contextName string) (string, error) {
	ref := credstore.ParseRef(b.Password)
	if !ref.IsRef {
		return b.Password, nil
	}
	backend, err := b.credentialBackend(ref.BackendName)
	if err != nil {
		return "", err
	}
	password, err := backend.Get(ctx, contextName)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("resolve password for context %q", contextName), err)
	}
	return password, nil
}

func (b Base) credentialBackend(name string) (credstore.Backend, error) {
	if name == "vault" {
		return credstore.NewVault(credstore.VaultConfig{
			Addr:      b.VaultAddr,
			Path:      b.VaultPath,
			RoleID:    b.VaultRoleID,
			Namespace: b.VaultNamespace,
		}), nil
	}
	return credstore.New(name)
}

// Config is the top-level context file structure.
type Config[T any] struct {
	APIVersion     string       `yaml:"apiVersion"`
	CurrentContext string       `yaml:"current-context"`
	Contexts       map[string]T `yaml:"contexts"`
}

// Options configures package-level context storage defaults.
type Options struct {
	APIVersion    string
	ConfigDirName string
}

var options = Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"}
var configPathOverride string

// Configure sets package-level context storage defaults for a consumer CLI.
func Configure(next Options) {
	if next.APIVersion != "" {
		options.APIVersion = next.APIVersion
	}
	if next.ConfigDirName != "" {
		options.ConfigDirName = next.ConfigDirName
	}
}

// SetConfigPath overrides the default config path for this process.
func SetConfigPath(path string) { configPathOverride = path }

// ConfigDir returns the configuration directory.
func ConfigDir() (string, error) {
	if configPathOverride != "" {
		return filepath.Dir(configPathOverride), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, options.ConfigDirName), nil
}

type BaseAccessor[T any] func(*T) *Base

// Store provides typed context persistence for a CLI-specific context type.
type Store[T any] struct{ base BaseAccessor[T] }

// NewStore creates a typed context store.
func NewStore[T any](base BaseAccessor[T]) Store[T] { return Store[T]{base: base} }

// Load reads the context config file. Missing file returns an empty config.
func (s Store[T]) Load() (*Config[T], error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	if err := enforceContextFileMode(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return emptyConfig[T](), nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read context file", err)
	}
	cfg, err := s.decode(data, true)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the full config under a file lock.
func (s Store[T]) Save(cfg *Config[T]) error {
	return s.Update(func(current *Config[T]) error {
		current.APIVersion = cfg.APIVersion
		current.CurrentContext = cfg.CurrentContext
		current.Contexts = cfg.Contexts
		return nil
	})
}

// Update performs a locked read-modify-write cycle.
func (s Store[T]) Update(fn func(cfg *Config[T]) error) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create config directory", err)
	}
	lock := lockfile.New(filepath.Join(dir, "config"))
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	cfg, err := s.loadUnlocked()
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	cfg.APIVersion = options.APIVersion
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]T)
	}
	return writeUnlocked(cfg)
}

// Current returns the active context.
func (s Store[T]) Current() (*T, string, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, "", err
	}
	if cfg.CurrentContext == "" {
		return nil, "", apperrors.New(apperrors.CodeUsageError, "no current context set", nil)
	}
	ctx, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return nil, "", apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", cfg.CurrentContext), nil)
	}
	return &ctx, cfg.CurrentContext, nil
}

// SetContext adds or updates a context.
func (s Store[T]) SetContext(name string, ctx T) error {
	return s.Update(func(cfg *Config[T]) error {
		cfg.Contexts[name] = ctx
		return nil
	})
}

// UseContext switches the current context.
func (s Store[T]) UseContext(name string) error {
	return s.Update(func(cfg *Config[T]) error {
		if _, ok := cfg.Contexts[name]; !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
		}
		cfg.CurrentContext = name
		return nil
	})
}

// DeleteContext removes a context.
func (s Store[T]) DeleteContext(name string) error {
	return s.Update(func(cfg *Config[T]) error {
		if _, ok := cfg.Contexts[name]; !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
		}
		delete(cfg.Contexts, name)
		if cfg.CurrentContext == name {
			cfg.CurrentContext = ""
		}
		return nil
	})
}

func configPath() (string, error) {
	if configPathOverride != "" {
		return configPathOverride, nil
	}
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func emptyConfig[T any]() *Config[T] {
	return &Config[T]{APIVersion: options.APIVersion, Contexts: make(map[string]T)}
}

func (s Store[T]) loadUnlocked() (*Config[T], error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return emptyConfig[T](), nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read context file", err)
	}
	return s.decode(data, false)
}

func (s Store[T]) decode(data []byte, allowEmptyVersion bool) (*Config[T], error) {
	var cfg Config[T]
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to parse context file", err)
	}
	if allowEmptyVersion && cfg.APIVersion == "" {
		cfg.APIVersion = options.APIVersion
	}
	if cfg.APIVersion != "" && cfg.APIVersion != options.APIVersion {
		return nil, apperrors.New(apperrors.CodeUnsupportedProtocol,
			fmt.Sprintf("unsupported context apiVersion %q; supported: %q", cfg.APIVersion, options.APIVersion), nil)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]T)
	}
	s.applyLoadedContextDefaults(data, &cfg)
	for name, item := range cfg.Contexts {
		base := s.base(&item)
		if base == nil {
			continue
		}
		ref := credstore.ParseRef(base.Password)
		if ref.IsRef && ref.BackendName == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q has empty credential store reference", name), nil)
		}
	}
	return &cfg, nil
}

func (s Store[T]) applyLoadedContextDefaults(data []byte, cfg *Config[T]) {
	if cfg == nil || len(cfg.Contexts) == 0 {
		return
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	contexts := mappingValue(doc.Content[0], "contexts")
	if contexts == nil || contexts.Kind != yaml.MappingNode {
		return
	}
	for name, item := range cfg.Contexts {
		base := s.base(&item)
		if base == nil {
			continue
		}
		itemNode := mappingValue(contexts, name)
		if itemNode != nil && itemNode.Kind == yaml.MappingNode && mappingValue(itemNode, "otlpRedact") == nil {
			base.OTLPRedact = true
			if base.OTLPEndpointSource == "" {
				base.OTLPEndpointSource = "auto"
			}
		}
		if base.OTLPEndpointSource == "" {
			base.OTLPEndpointSource = "auto"
		}
		if base.OTLPMetricsSource == "" {
			base.OTLPMetricsSource = "auto"
		}
		if base.BackupKeep == 0 && !mappingHasField(itemNode, "backupKeep") {
			base.BackupKeep = 10
		}
		cfg.Contexts[name] = item
	}
}

func mappingHasField(node *yaml.Node, field string) bool { return mappingValue(node, field) != nil }

func mappingValue(node *yaml.Node, key string) *yaml.Node {
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

func writeUnlocked[T any](cfg *Config[T]) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal context file", err)
	}
	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open temp context file", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write temp context file", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close temp context file", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return apperrors.New(apperrors.CodeLocalIOError, "failed to replace context file", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to set context file permissions", err)
	}
	return setOwnerOnlyACL(path)
}

func enforceContextFileMode(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to stat context file", err)
	}
	if info.IsDir() {
		return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("context path %q is a directory", path), nil)
	}
	if runtime.GOOS == "windows" {
		return enforceWindowsContextFileACL(path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("context file %s has insecure mode %#o", path, info.Mode().Perm()), nil)
	}
	return checkFileOwner(info, path)
}

func enforceWindowsContextFileACL(path string) error {
	if err := verifyOwnerOnlyACL(path); err == nil {
		return nil
	}
	if err := setOwnerOnlyACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("context file %s has insecure ACL and auto-fix failed: %v", path, err), nil)
	}
	if err := verifyOwnerOnlyACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("context file %s still has insecure ACL after auto-fix: %v", path, err), nil)
	}
	return nil
}
