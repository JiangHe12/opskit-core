package credstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/securefile"
)

const (
	encryptedFileName    = "credentials.enc"
	encryptedFileVersion = byte(0x01)
	encryptedSaltSize    = 16
	encryptedNonceSize   = 12
	encryptedKeySize     = 32
	argonTime            = 3
	argonMemory          = 64 * 1024
	argonThreads         = 4
)

type encryptedFileBackend struct {
	mu   sync.Mutex
	path string
}

func (e *encryptedFileBackend) Name() string { return "encrypted-file" }

func (e *encryptedFileBackend) Available() error {
	if os.Getenv(options.MasterPasswordEnv) == "" {
		return fmt.Errorf("encrypted-file: %s not set", options.MasterPasswordEnv)
	}
	return nil
}

func (e *encryptedFileBackend) Get(_ context.Context, contextName string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries, err := e.readEntries()
	if err != nil {
		return "", err
	}
	password, ok := entries[contextName]
	if !ok {
		return "", ErrNotFound
	}
	return password, nil
}

func (e *encryptedFileBackend) Put(_ context.Context, contextName, password string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.withMutationLock(func() error {
		entries, err := e.readEntries()
		if errors.Is(err, ErrNotFound) {
			entries = make(map[string]string)
		} else if err != nil {
			return err
		}
		entries[contextName] = password
		return e.writeEntries(entries)
	})
}

func (e *encryptedFileBackend) Delete(_ context.Context, contextName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.withMutationLock(func() error {
		entries, err := e.readEntries()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, ok := entries[contextName]; !ok {
			return nil
		}
		delete(entries, contextName)
		return e.writeEntries(entries)
	})
}

func (e *encryptedFileBackend) withMutationLock(mutate func() error) error {
	path, err := e.filePath()
	if err != nil {
		return err
	}
	if err := securefile.EnsureParent(path); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to create credential directory", err)
	}
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to lock encrypted credentials", err)
	}
	operationErr := mutate()
	if releaseErr := lock.Release(); releaseErr != nil {
		if operationErr != nil {
			return apperrors.New(
				apperrors.CodeCredentialStoreError,
				"encrypted credential update failed and its lock could not be released",
				errors.Join(operationErr, releaseErr),
			)
		}
		return apperrors.New(
			apperrors.CodePartialFailure,
			"encrypted credentials were updated but their lock could not be released",
			releaseErr,
		).WithSuggestion("verify the credential and lock state before retrying")
	}
	return operationErr
}

func (e *encryptedFileBackend) readEntries() (map[string]string, error) {
	path, err := e.filePath()
	if err != nil {
		return nil, err
	}
	data, err := securefile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to read encrypted credentials", err)
	}
	plain, err := e.decrypt(data)
	if err != nil {
		return nil, err
	}
	var entries map[string]string
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to parse encrypted credentials", err)
	}
	if entries == nil {
		entries = make(map[string]string)
	}
	return entries, nil
}

func (e *encryptedFileBackend) writeEntries(entries map[string]string) error {
	path, err := e.filePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to marshal encrypted credentials", err)
	}
	encrypted, err := e.encrypt(data)
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(path, encrypted); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to replace encrypted credentials", err)
	}
	return nil
}

func (e *encryptedFileBackend) encrypt(plain []byte) ([]byte, error) {
	passphrase, err := masterPassphrase()
	if err != nil {
		return nil, err
	}
	salt, err := randomBytes(encryptedSaltSize)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(encryptedNonceSize)
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential cipher", err)
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, len(options.EncryptedFileMagic)+1+len(salt)+len(nonce)+len(sealed))
	out = append(out, options.EncryptedFileMagic...)
	out = append(out, encryptedFileVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (e *encryptedFileBackend) decrypt(data []byte) ([]byte, error) {
	headerSize := len(options.EncryptedFileMagic) + 1 + encryptedSaltSize + encryptedNonceSize
	if len(data) < headerSize+16 || !bytes.Equal(data[:len(options.EncryptedFileMagic)], options.EncryptedFileMagic) {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "invalid encrypted credential file", nil)
	}
	if data[len(options.EncryptedFileMagic)] != encryptedFileVersion {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "unsupported encrypted credential file version", nil)
	}
	offset := len(options.EncryptedFileMagic) + 1
	salt := data[offset : offset+encryptedSaltSize]
	offset += encryptedSaltSize
	nonce := data[offset : offset+encryptedNonceSize]
	offset += encryptedNonceSize
	ciphertext := data[offset:]
	passphrase, err := masterPassphrase()
	if err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential cipher", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to decrypt credentials (wrong password or corrupted file)", nil)
	}
	return plain, nil
}

func (e *encryptedFileBackend) filePath() (string, error) {
	if e.path != "" {
		return e.path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, "failed to resolve user home directory", err)
	}
	return filepath.Join(home, options.ConfigDirName, encryptedFileName), nil
}

func masterPassphrase() ([]byte, error) {
	if value := os.Getenv(options.MasterPasswordEnv); value != "" {
		return []byte(value), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, apperrors.New(apperrors.CodeAuthorizationRequired, fmt.Sprintf("encrypted-file backend requires %s env", options.MasterPasswordEnv), nil)
	}
	_, _ = fmt.Fprintf(os.Stderr, "Enter %s master password: ", options.PromptName)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeAuthorizationRequired, fmt.Sprintf("failed to read %s master password", options.PromptName), err)
	}
	if len(value) == 0 {
		return nil, apperrors.New(apperrors.CodeAuthorizationRequired, fmt.Sprintf("encrypted-file backend requires %s env", options.MasterPasswordEnv), nil)
	}
	return value, nil
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, encryptedKeySize)
}

func randomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to generate credential randomness", err)
	}
	return out, nil
}
