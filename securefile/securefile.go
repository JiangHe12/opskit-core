// Package securefile provides owner-only, atomic local file persistence.
//
// Callers that perform read-modify-write operations remain responsible for
// holding their domain lock across the complete operation.
package securefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const maxTempCreateAttempts = 100

type writeRuntime struct {
	write      func(*os.File, []byte) (int, error)
	sync       func(*os.File) error
	close      func(*os.File) error
	replace    func(string, string) error
	syncParent func(string) error
	remove     func(string) error
}

var productionWriteRuntime = writeRuntime{
	write: func(file *os.File, data []byte) (int, error) {
		return file.Write(data)
	},
	sync: func(file *os.File) error {
		return file.Sync()
	},
	close: func(file *os.File) error {
		return file.Close()
	},
	replace:    atomicReplaceFile,
	syncParent: syncParentDirectory,
	remove:     os.Remove,
}

// EnsureParent creates missing parent directories with owner-only permissions
// and validates the complete existing directory chain.
func EnsureParent(path string) error {
	resolved, err := resolveTarget(path)
	if err != nil {
		return err
	}
	return walkDirectoryChain(filepath.Dir(resolved), true)
}

// CheckFile validates a file and its parent directory chain. Missing files are
// reported as exists=false and are not created.
func CheckFile(path string) (bool, error) {
	resolved, err := resolveTarget(path)
	if err != nil {
		return false, err
	}
	if err := walkDirectoryChain(filepath.Dir(resolved), false); err != nil {
		if isNotExist(err) {
			return false, nil
		}
		return false, err
	}
	file, err := openOwnerOnlyFile(resolved)
	if isNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "failed to validate secure file", err)
	}
	if err := file.Close(); err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "failed to close secure file", err)
	}
	return true, nil
}

// ReadFile reads a validated owner-only regular file without following a
// symlink or Windows reparse point.
func ReadFile(path string) ([]byte, error) {
	resolved, err := resolveTarget(path)
	if err != nil {
		return nil, err
	}
	if err := walkDirectoryChain(filepath.Dir(resolved), false); err != nil {
		return nil, err
	}
	file, err := openOwnerOnlyFile(resolved)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to open secure file", err)
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read secure file", readErr)
	}
	if closeErr != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to close secure file", closeErr)
	}
	return data, nil
}

// WriteFile atomically replaces path with owner-only data. It uses a random,
// exclusively-created temporary file in the same directory, syncs the file
// before replacement, and syncs the parent directory on Unix.
func WriteFile(path string, data []byte) error {
	return writeFileWithRuntime(path, data, productionWriteRuntime)
}

func writeFileWithRuntime(path string, data []byte, runtime writeRuntime) (retErr error) {
	resolved, err := resolveTarget(path)
	if err != nil {
		return err
	}
	if err := walkDirectoryChain(filepath.Dir(resolved), true); err != nil {
		return err
	}
	existed, err := checkResolvedFile(resolved)
	if err != nil {
		return err
	}

	file, tempPath, err := createOwnerOnlyTemp(
		filepath.Dir(resolved),
		"."+filepath.Base(resolved)+".tmp-",
	)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create secure temporary file", err)
	}
	defer func() {
		if tempPath == "" {
			return
		}
		if file != nil {
			_ = file.Close()
		}
		if err := runtime.remove(tempPath); err != nil && !isNotExist(err) {
			cleanupErr := apperrors.New(
				apperrors.CodeLocalIOError,
				"failed to clean secure temporary file",
				err,
			)
			if retErr == nil {
				retErr = cleanupErr
			} else {
				retErr = errors.Join(retErr, cleanupErr)
			}
		}
	}()

	written, err := runtime.write(file, data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write secure temporary file", err)
	}
	if err := runtime.sync(file); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync secure temporary file", err)
	}
	if err := runtime.close(file); err != nil {
		_ = file.Close()
		file = nil
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close secure temporary file", err)
	}
	file = nil

	if err := walkDirectoryChain(filepath.Dir(resolved), false); err != nil {
		return err
	}
	existsNow, err := checkResolvedFile(resolved)
	if err != nil {
		return err
	}
	if existsNow != existed {
		return apperrors.New(
			apperrors.CodeConflict,
			"secure file target changed while replacement was prepared",
			nil,
		)
	}
	if err := runtime.replace(tempPath, resolved); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to atomically replace secure file", err)
	}
	tempPath = ""
	if err := runtime.syncParent(resolved); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync secure file parent directory", err)
	}
	return nil
}

func checkResolvedFile(path string) (bool, error) {
	file, err := openOwnerOnlyFile(path)
	if isNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "secure file target is invalid", err)
	}
	if err := file.Close(); err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "failed to close secure file target", err)
	}
	return true, nil
}

func createOwnerOnlyTemp(directory, prefix string) (*os.File, string, error) {
	for range maxTempCreateAttempts {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		path := filepath.Join(directory, prefix+hex.EncodeToString(random[:]))
		file, err := createOwnerOnlyExclusive(path)
		if err == nil {
			return file, path, nil
		}
		if isPathExistError(err) {
			continue
		}
		return nil, "", err
	}
	return nil, "", apperrors.New(
		apperrors.CodeConflict,
		"failed to allocate a unique secure temporary file",
		nil,
	)
}

func resolveTarget(path string) (string, error) {
	if path == "" {
		return "", apperrors.New(apperrors.CodeLocalIOError, "secure file path is empty", nil)
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve secure file path", err)
	}
	resolved = filepath.Clean(resolved)
	if filepath.Dir(resolved) == resolved {
		return "", apperrors.New(apperrors.CodeLocalIOError, "secure file path must name a file", nil)
	}
	return resolved, nil
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

func walkDirectoryChain(path string, create bool) error {
	chain, err := directoryChain(path)
	if err != nil {
		return err
	}
	for index, directory := range chain {
		info, inspectErr := os.Lstat(directory)
		created := false
		if os.IsNotExist(inspectErr) && create {
			if err := createOwnerOnlyDirectory(directory); err != nil {
				if !isPathExistError(err) {
					return apperrors.New(
						apperrors.CodeLocalIOError,
						"failed to create secure file directory",
						err,
					)
				}
			} else {
				created = true
			}
			info, inspectErr = os.Lstat(directory)
		}
		if inspectErr != nil {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				"failed to inspect secure file directory",
				inspectErr,
			)
		}
		if err := validateDirectory(info, directory, index == len(chain)-1, created); err != nil {
			return err
		}
	}
	return nil
}

func directoryChain(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to resolve secure file directory",
			err,
		)
	}
	current := filepath.Clean(absolute)
	reversed := []string{}
	for {
		reversed = append(reversed, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	chain := make([]string, len(reversed))
	for index := range reversed {
		chain[len(reversed)-1-index] = reversed[index]
	}
	return chain, nil
}
