package credstore

// Options configures package-level defaults for credential backends.
type Options struct {
	MasterPasswordEnv     string
	PromptName            string
	ConfigDirName         string
	KeychainService       string
	KeychainAccountPrefix string
	EncryptedFileMagic    []byte
}

var options = Options{
	MasterPasswordEnv:     "OPSKIT_MASTER_PASSWORD",
	PromptName:            "opskit",
	ConfigDirName:         ".opskit",
	KeychainService:       "opskit",
	KeychainAccountPrefix: "",
	EncryptedFileMagic:    []byte("OPSKIT01"),
}

// Configure sets package-level defaults for credential backends.
func Configure(next Options) {
	if next.MasterPasswordEnv != "" {
		options.MasterPasswordEnv = next.MasterPasswordEnv
	}
	if next.PromptName != "" {
		options.PromptName = next.PromptName
	}
	if next.ConfigDirName != "" {
		options.ConfigDirName = next.ConfigDirName
	}
	if next.KeychainService != "" {
		options.KeychainService = next.KeychainService
	}
	options.KeychainAccountPrefix = next.KeychainAccountPrefix
	if len(next.EncryptedFileMagic) > 0 {
		options.EncryptedFileMagic = append([]byte(nil), next.EncryptedFileMagic...)
	}
}
