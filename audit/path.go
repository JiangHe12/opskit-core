package audit

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const maxTempCreateAttempts = 100

func auditDirectoryChain(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit directory", err)
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

func createOwnerOnlyTemp(directory, prefix string) (*os.File, string, error) {
	for range maxTempCreateAttempts {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", apperrors.New(apperrors.CodeLocalIOError, "failed to generate audit temp name", err)
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
	return nil, "", apperrors.New(apperrors.CodeConflict, "failed to allocate unique audit temp file", nil)
}
