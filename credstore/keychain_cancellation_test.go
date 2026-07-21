package credstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

var errKeychainMutationFault = errors.New("injected keychain mutation fault")

func TestKeychainMutationsHonorCancellationBeforeStart(t *testing.T) {
	originalSet := keychainSet
	originalDelete := keychainDelete
	defer func() {
		keychainSet = originalSet
		keychainDelete = originalDelete
	}()
	var calls atomic.Int32
	keychainSet = func(string, string, string) error {
		calls.Add(1)
		return nil
	}
	keychainDelete = func(string, string) error {
		calls.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := &keychainBackend{}

	if err := backend.Put(ctx, "prod", "secret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context canceled", err)
	}
	if err := backend.Delete(ctx, "prod"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v, want context canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("keychain mutations called %d times after pre-start cancellation", calls.Load())
	}
}

func TestKeychainMutationsWaitForDefiniteResultAfterStart(t *testing.T) {
	for _, test := range []struct {
		name    string
		install func(started chan<- struct{}, release <-chan struct{})
		call    func(context.Context, *keychainBackend) error
		wantErr error
	}{
		{
			name: "put",
			install: func(started chan<- struct{}, release <-chan struct{}) {
				keychainSet = func(string, string, string) error {
					close(started)
					<-release
					return nil
				}
			},
			call: func(ctx context.Context, backend *keychainBackend) error {
				return backend.Put(ctx, "prod", "secret")
			},
		},
		{
			name: "put error",
			install: func(started chan<- struct{}, release <-chan struct{}) {
				keychainSet = func(string, string, string) error {
					close(started)
					<-release
					return errKeychainMutationFault
				}
			},
			call: func(ctx context.Context, backend *keychainBackend) error {
				return backend.Put(ctx, "prod", "secret")
			},
			wantErr: errKeychainMutationFault,
		},
		{
			name: "delete not found",
			install: func(started chan<- struct{}, release <-chan struct{}) {
				keychainDelete = func(string, string) error {
					close(started)
					<-release
					return keyring.ErrNotFound
				}
			},
			call: func(ctx context.Context, backend *keychainBackend) error {
				return backend.Delete(ctx, "prod")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalSet := keychainSet
			originalDelete := keychainDelete
			defer func() {
				keychainSet = originalSet
				keychainDelete = originalDelete
			}()
			started := make(chan struct{})
			release := make(chan struct{})
			test.install(started, release)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- test.call(ctx, &keychainBackend{})
			}()
			<-started
			cancel()

			select {
			case err := <-done:
				t.Fatalf("mutation returned before the OS result was known: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			if err := <-done; !errors.Is(err, test.wantErr) {
				t.Fatalf("mutation result = %v, want %v", err, test.wantErr)
			}
		})
	}
}
