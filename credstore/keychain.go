package credstore

import (
	"context"
	"errors"
	"sync"

	"github.com/zalando/go-keyring"
)

type keychainBackend struct {
	availableOnce sync.Once
	availableErr  error
}

var (
	keychainGet    = keyring.Get
	keychainSet    = keyring.Set
	keychainDelete = keyring.Delete
)

func (k *keychainBackend) Name() string { return "keychain" }

func (k *keychainBackend) Available() error {
	k.availableOnce.Do(func() {
		_, err := keychainGet(options.KeychainService, keychainAccount("__probe__"))
		if errors.Is(err, keyring.ErrNotFound) {
			return
		}
		if err != nil {
			k.availableErr = errors.New("keychain: not available on this platform")
		}
	})
	return k.availableErr
}

func (k *keychainBackend) Get(ctx context.Context, contextName string) (string, error) {
	type result struct {
		password string
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		password, err := keychainGet(options.KeychainService, keychainAccount(contextName))
		ch <- result{password: password, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-ch:
		if errors.Is(result.err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return result.password, result.err
	}
}

func (k *keychainBackend) Put(ctx context.Context, contextName, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// OS keychain APIs do not provide transactional cancellation. Once the
	// mutation starts, wait for its definite result so a canceled context
	// cannot conceal a credential that was committed in the background.
	return keychainSet(options.KeychainService, keychainAccount(contextName), password)
}

func (k *keychainBackend) Delete(ctx context.Context, contextName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// As with Put, cancellation is honored before the mutation starts. After
	// that boundary, returning the keychain's result preserves a determinate
	// migration/compensation decision for callers.
	err := keychainDelete(options.KeychainService, keychainAccount(contextName))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

func keychainAccount(contextName string) string {
	return options.KeychainAccountPrefix + contextName
}
