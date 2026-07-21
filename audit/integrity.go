package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const (
	envelopeAPIVersion   = "opskit-core.io/audit/v2"
	envelopeKind         = "AuditEnvelope"
	checkpointAPIVersion = "opskit-core.io/audit-checkpoint/v1"
	checkpointKind       = "AuditCheckpoint"
	keyAPIVersion        = "opskit-core.io/audit-hmac-key/v1"
	keyKind              = "AuditHMACKey"

	payloadEncodingJSON = "json"
	payloadEncodingAge  = "age-x25519"

	integrityKeySize  = 32
	macSize           = sha256.Size
	maxAuditLineBytes = 4 * 1024 * 1024

	maxIntegrityKeyFileBytes = 4 * 1024
	maxCheckpointFileBytes   = 16 * 1024
)

var (
	envelopeMACDomain   = []byte("opskit-core.audit.envelope.v2")
	checkpointMACDomain = []byte("opskit-core.audit.checkpoint.v1")
)

type auditEnvelope struct {
	APIVersion      string          `json:"apiVersion"`
	Kind            string          `json:"kind"`
	KeyID           string          `json:"keyId"`
	Sequence        uint64          `json:"sequence"`
	PrevMAC         string          `json:"prevMac,omitempty"`
	PayloadEncoding string          `json:"payloadEncoding"`
	Payload         json.RawMessage `json:"payload"`
	MAC             string          `json:"mac"`
}

type auditCheckpoint struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	KeyID        string `json:"keyId"`
	BaseSequence uint64 `json:"baseSequence"`
	BaseMAC      string `json:"baseMac,omitempty"`
	HeadSequence uint64 `json:"headSequence"`
	HeadMAC      string `json:"headMac,omitempty"`
	MAC          string `json:"mac"`
}

type integrityKeyFile struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Key        string `json:"key"`
}

type envelopePayload struct {
	plain      []byte
	ciphertext []byte
	encoding   string
	raw        json.RawMessage
}

func prepareAppendIntegrity(path, keyPath string) ([]byte, auditCheckpoint, bool, error) {
	if err := validateIntegrityKeyPath(path, keyPath); err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	checkpointOnDisk, err := pathExists(checkpointPath(path))
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	keyOnDisk, err := pathExists(keyPath)
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	if checkpointOnDisk && !keyOnDisk {
		return nil, auditCheckpoint{}, false,
			apperrors.New(apperrors.CodeValidationFailed, "audit integrity key is missing for authenticated audit history", nil)
	}
	if !keyOnDisk {
		hasV2, scanErr := auditContainsV2(path)
		if scanErr != nil {
			return nil, auditCheckpoint{}, false, scanErr
		}
		if hasV2 {
			return nil, auditCheckpoint{}, false,
				apperrors.New(apperrors.CodeValidationFailed, "audit integrity key is missing for authenticated audit history", nil)
		}
		key, createErr := createIntegrityKey(keyPath)
		return key, auditCheckpoint{}, false, createErr
	}
	key, err := loadIntegrityKey(keyPath)
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	checkpoint, checkpointExists, err := loadCheckpoint(path, key)
	if err != nil {
		return nil, auditCheckpoint{}, checkpointExists, err
	}
	if checkpointExists {
		checkpoint, err = reconcileAppendCheckpoint(path, checkpoint, key)
		if err != nil {
			return nil, auditCheckpoint{}, true, err
		}
		return key, checkpoint, true, nil
	}
	hasV2, err := auditContainsV2(path)
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	if hasV2 {
		return nil, auditCheckpoint{}, false,
			apperrors.New(apperrors.CodeValidationFailed, "audit checkpoint is missing for authenticated audit history", nil)
	}
	return key, auditCheckpoint{}, false, nil
}

func reconcileAppendCheckpoint(path string, checkpoint auditCheckpoint, key []byte) (auditCheckpoint, error) {
	baseSequence, baseMAC, err := checkpointBase(checkpoint)
	if err != nil {
		return auditCheckpoint{}, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint base", err)
	}
	headSequence, headMAC, err := checkpointHead(checkpoint)
	if err != nil {
		return auditCheckpoint{}, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint head", err)
	}
	line, found, err := lastStoredLine(path)
	if err != nil {
		return auditCheckpoint{}, err
	}
	if !found {
		if headSequence == baseSequence {
			return checkpoint, nil
		}
		return auditCheckpoint{}, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit history is truncated before its checkpoint head",
			nil,
		)
	}
	env, payload, isEnvelope, parseErr := parseEnvelope([]byte(line))
	if parseErr == nil && isEnvelope {
		_, mac, verifyErr := verifyEnvelope(env, payload, key)
		if verifyErr == nil && env.Sequence == headSequence && hmac.Equal(mac, headMAC) {
			return checkpoint, nil
		}
	}

	recoveredSequence, recoveredMAC, recoveredLag, recoverErr := verifyCheckpointRecovery(
		path,
		key,
		baseSequence,
		baseMAC,
		headSequence,
	)
	if recoverErr != nil {
		return auditCheckpoint{}, recoverErr
	}
	if !recoveredLag {
		return checkpoint, nil
	}
	nextCheckpoint := makeCheckpoint(key, baseSequence, baseMAC, recoveredSequence, recoveredMAC)
	if err := writeCheckpoint(path, nextCheckpoint); err != nil {
		return auditCheckpoint{}, err
	}
	return nextCheckpoint, nil
}

func verifyCheckpointRecovery(
	path string,
	key []byte,
	baseSequence uint64,
	baseMAC []byte,
	checkpointHead uint64,
) (uint64, []byte, bool, error) {
	sequence := baseSequence
	mac := append([]byte(nil), baseMAC...)
	seenV2 := baseSequence > 0
	observedV2 := false
	files, err := queryFiles(path)
	if err != nil {
		return 0, nil, false, err
	}
	for _, filePath := range files {
		file, openErr := openAuditReadFile(filePath)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				continue
			}
			return 0, nil, false, openErr
		}
		scanner := newAuditScanner(file)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			env, payload, isEnvelope, parseErr := parseEnvelope(line)
			if parseErr != nil {
				_ = file.Close()
				return 0, nil, false, apperrors.New(apperrors.CodeValidationFailed, "invalid audit envelope during checkpoint recovery", parseErr)
			}
			if !isEnvelope {
				if seenV2 {
					_ = file.Close()
					return 0, nil, false, apperrors.New(
						apperrors.CodeValidationFailed,
						"unauthenticated audit record follows authenticated history",
						nil,
					)
				}
				continue
			}
			prevMAC, nextMAC, verifyErr := verifyEnvelope(env, payload, key)
			if verifyErr != nil || env.Sequence != sequence+1 || !hmac.Equal(prevMAC, mac) {
				_ = file.Close()
				return 0, nil, false, apperrors.New(
					apperrors.CodeValidationFailed,
					"audit chain cannot recover its lagging checkpoint",
					verifyErr,
				)
			}
			seenV2 = true
			observedV2 = true
			sequence = env.Sequence
			mac = nextMAC
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return 0, nil, false, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", scanErr)
		}
		if closeErr != nil {
			return 0, nil, false, apperrors.New(apperrors.CodeLocalIOError, "failed to close audit log", closeErr)
		}
	}
	if !observedV2 && checkpointHead == baseSequence {
		return sequence, mac, false, nil
	}
	if !observedV2 || checkpointHead == math.MaxUint64 || sequence != checkpointHead+1 {
		return 0, nil, false, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit log head does not match its checkpoint",
			nil,
		)
	}
	return sequence, mac, true, nil
}

func auditContainsV2(path string) (bool, error) {
	files, err := queryFiles(path)
	if err != nil {
		return false, err
	}
	for _, filePath := range files {
		found, err := fileContainsV2(filePath)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

func openAuditReadFile(path string) (*os.File, error) {
	if err := verifyOwnerOnlyFile(path); err != nil {
		return nil, err
	}
	if err := validateAuditArtifactParent(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path) //nolint:gosec // The path was validated as a regular non-link file.
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", err)
	}
	return file, nil
}

func validateAuditArtifactParent(path string) error {
	directory := filepath.Clean(filepath.Dir(path))
	return validateAuditDirectoryChain(directory, true)
}

func fileContainsV2(path string) (bool, error) {
	file, err := openAuditReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = file.Close() }()
	scanner := newAuditScanner(file)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) > 0 && looksLikeEnvelope(line) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	return false, nil
}

func lastStoredLine(path string) (string, bool, error) {
	line, found, err := lastLineInFile(path)
	if err != nil {
		return "", false, err
	}
	if found {
		return line, true, nil
	}

	rotated, err := RotatedFiles(path)
	if err != nil {
		return "", false, err
	}
	for index := len(rotated) - 1; index >= 0; index-- {
		line, found, err = lastLineInFile(rotated[index])
		if err != nil {
			return "", false, err
		}
		if found {
			return line, true, nil
		}
	}
	return "", false, nil
}

func lastLineInFile(path string) (string, bool, error) {
	file, err := openAuditReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", false, apperrors.New(apperrors.CodeLocalIOError, "failed to stat audit log", err)
	}
	if info.Size() == 0 {
		return "", false, nil
	}

	const tailBlockSize = 64 * 1024
	position := info.Size()
	reversedLine := make([]byte, 0, tailBlockSize)
	for position > 0 {
		readSize := int64(tailBlockSize)
		if position < readSize {
			readSize = position
		}
		position -= readSize
		block := make([]byte, int(readSize))
		if _, err := file.ReadAt(block, position); err != nil && !errors.Is(err, io.EOF) {
			return "", false, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log tail", err)
		}
		for index := len(block) - 1; index >= 0; index-- {
			if block[index] == '\n' {
				if line, found := finishReversedAuditLine(reversedLine); found {
					return line, true, nil
				}
				reversedLine = reversedLine[:0]
				continue
			}
			reversedLine = append(reversedLine, block[index])
			if len(reversedLine) > maxAuditLineBytes {
				return "", false, apperrors.New(
					apperrors.CodeValidationFailed,
					"audit log line exceeds the maximum supported size",
					nil,
				)
			}
		}
	}
	if line, found := finishReversedAuditLine(reversedLine); found {
		return line, true, nil
	}
	return "", false, nil
}

func finishReversedAuditLine(reversed []byte) (string, bool) {
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	line := strings.TrimSpace(string(reversed))
	return line, line != ""
}

func newAuditScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), maxAuditLineBytes+1)
	return scanner
}

func pathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
		}
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit path", err)
}

func defaultIntegrityKeyPath(path string) string { return path + ".hmac-key" }
func checkpointPath(path string) string          { return path + ".checkpoint" }

func effectiveIntegrityKeyPath(path, override string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	return defaultIntegrityKeyPath(path)
}

func validateIntegrityKeyPath(path, keyPath string) error {
	auditPath, err := canonicalAuditPath(path)
	if err != nil {
		return err
	}
	keyPath, err = canonicalAuditPath(keyPath)
	if err != nil {
		return err
	}
	defaultKeyPath, err := canonicalAuditPath(defaultIntegrityKeyPath(path))
	if err != nil {
		return err
	}
	isDefaultKeyPath := auditPathEqual(keyPath, defaultKeyPath)
	if !isDefaultKeyPath &&
		(auditPathEqual(keyPath, auditPath) || auditPathHasPrefix(keyPath, auditPath+".")) {
		return integrityKeyPathConflict()
	}

	keyInfo, err := os.Stat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit integrity key alias", err)
	}
	entries, err := os.ReadDir(filepath.Dir(auditPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit artifact aliases", err)
	}
	activeBase := filepath.Base(auditPath)
	for _, entry := range entries {
		if !auditPathEqual(entry.Name(), activeBase) &&
			!auditPathHasPrefix(entry.Name(), activeBase+".") {
			continue
		}
		artifactPath := filepath.Join(filepath.Dir(auditPath), entry.Name())
		if auditPathEqual(artifactPath, keyPath) {
			continue
		}
		artifactInfo, statErr := os.Stat(artifactPath)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit artifact alias", statErr)
		}
		if os.SameFile(keyInfo, artifactInfo) {
			return integrityKeyPathConflict()
		}
	}
	return nil
}

func canonicalAuditPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit path", err)
	}
	current := filepath.Clean(absolute)
	missing := []string{}
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit path aliases", resolveErr)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absolute), nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func auditPathHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && auditPathEqual(value[:len(prefix)], prefix)
}

func integrityKeyPathConflict() error {
	return apperrors.New(
		apperrors.CodeValidationFailed,
		"audit integrity key path conflicts with the audit artifact namespace",
		nil,
	)
}

func newIntegrityKey() ([]byte, error) {
	key := make([]byte, integrityKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to generate audit integrity key", err)
	}
	return key, nil
}

func integrityKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func loadIntegrityKey(path string) ([]byte, error) {
	data, err := readBoundedOwnerOnlyArtifact(path, maxIntegrityKeyFileBytes, "audit integrity key")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "audit integrity key is missing", err)
		}
		return nil, err
	}
	var stored integrityKeyFile
	if err := strictDecodeObject(data, &stored); err != nil {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "invalid audit integrity key file", err)
	}
	if stored.APIVersion != keyAPIVersion || stored.Kind != keyKind {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "unsupported audit integrity key file", nil)
	}
	key, err := base64.RawStdEncoding.DecodeString(stored.Key)
	if err != nil || base64.RawStdEncoding.EncodeToString(key) != stored.Key || len(key) != integrityKeySize {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "invalid audit integrity key material", err)
	}
	return key, nil
}

func createIntegrityKey(path string) ([]byte, error) {
	if err := ensureOwnerOnlyDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	key, err := newIntegrityKey()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(integrityKeyFile{
		APIVersion: keyAPIVersion,
		Kind:       keyKind,
		Key:        base64.RawStdEncoding.EncodeToString(key),
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit integrity key", err)
	}
	file, err := createOwnerOnlyExclusive(path)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadIntegrityKey(path)
		}
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to create audit integrity key", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := verifyOwnerOnlyFile(path); err != nil {
		return nil, err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to write audit integrity key", err)
	}
	if err := file.Sync(); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit integrity key", err)
	}
	if err := file.Close(); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to close audit integrity key", err)
	}
	if err := verifyOwnerOnlyFile(path); err != nil {
		return nil, err
	}
	if err := syncParentDirectory(path); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit integrity key directory", err)
	}
	ok = true
	return key, nil
}

func encodeEnvelope(record any, publicKeyPath string, key []byte, sequence uint64, prevMAC []byte) ([]byte, []byte, error) {
	if sequence == 0 {
		return nil, nil, apperrors.New(apperrors.CodeValidationFailed, "audit sequence must be positive", nil)
	}
	plain, err := json.Marshal(record)
	if err != nil {
		return nil, nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit event", err)
	}
	if err := validateAuditLineSize(plain); err != nil {
		return nil, nil, err
	}
	payload, err := encodeEnvelopePayload(plain, publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	env := auditEnvelope{
		APIVersion:      envelopeAPIVersion,
		Kind:            envelopeKind,
		KeyID:           integrityKeyID(key),
		Sequence:        sequence,
		PrevMAC:         encodeMAC(prevMAC),
		PayloadEncoding: payload.encoding,
		Payload:         payload.raw,
	}
	mac := computeEnvelopeMAC(key, env, payloadMACBytes(payload))
	env.MAC = encodeMAC(mac)
	line, err := json.Marshal(env)
	if err != nil {
		return nil, nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit envelope", err)
	}
	if err := validateAuditLineSize(line); err != nil {
		return nil, nil, err
	}
	return line, mac, nil
}

func validateAuditLineSize(line []byte) error {
	if len(line) <= maxAuditLineBytes {
		return nil
	}
	return apperrors.New(
		apperrors.CodeValidationFailed,
		"audit log line exceeds the maximum supported size",
		nil,
	)
}

func encodeEnvelopePayload(plain []byte, publicKeyPath string) (envelopePayload, error) {
	if strings.TrimSpace(publicKeyPath) == "" {
		return envelopePayload{
			plain:    plain,
			encoding: payloadEncodingJSON,
			raw:      json.RawMessage(plain),
		}, nil
	}
	ciphertext, err := encryptAuditPayload(plain, publicKeyPath)
	if err != nil {
		return envelopePayload{}, err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	raw, err := json.Marshal(encoded)
	if err != nil {
		return envelopePayload{}, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal encrypted audit payload", err)
	}
	return envelopePayload{
		ciphertext: ciphertext,
		encoding:   payloadEncodingAge,
		raw:        raw,
	}, nil
}

func parseEnvelope(line []byte) (auditEnvelope, envelopePayload, bool, error) {
	if !looksLikeEnvelope(line) {
		return auditEnvelope{}, envelopePayload{}, false, nil
	}
	var env auditEnvelope
	if err := strictDecodeObject(line, &env); err != nil {
		return auditEnvelope{}, envelopePayload{}, true, err
	}
	if env.APIVersion != envelopeAPIVersion || env.Kind != envelopeKind {
		return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("unsupported audit envelope")
	}
	if env.Sequence == 0 {
		return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("audit sequence must be positive")
	}
	payload := envelopePayload{encoding: env.PayloadEncoding, raw: env.Payload}
	switch env.PayloadEncoding {
	case payloadEncodingJSON:
		if !json.Valid(env.Payload) {
			return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("invalid JSON audit payload")
		}
		payload.plain = append([]byte(nil), env.Payload...)
	case payloadEncodingAge:
		var encoded string
		if err := json.Unmarshal(env.Payload, &encoded); err != nil {
			return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("invalid encrypted audit payload: %w", err)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(ciphertext) != encoded {
			return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("invalid encrypted audit payload encoding")
		}
		if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1")) {
			return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("invalid age audit payload")
		}
		payload.ciphertext = ciphertext
	default:
		return auditEnvelope{}, envelopePayload{}, true, fmt.Errorf("unsupported audit payload encoding %q", env.PayloadEncoding)
	}
	return env, payload, true, nil
}

func verifyEnvelope(env auditEnvelope, payload envelopePayload, key []byte) ([]byte, []byte, error) {
	if env.KeyID != integrityKeyID(key) {
		return nil, nil, fmt.Errorf("audit envelope key ID mismatch")
	}
	prevMAC, err := decodeSequenceMAC(env.PrevMAC, env.Sequence-1)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid previous audit MAC: %w", err)
	}
	mac, err := decodeMAC(env.MAC, false)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid audit MAC: %w", err)
	}
	expected := computeEnvelopeMAC(key, env, payloadMACBytes(payload))
	if !hmac.Equal(mac, expected) {
		return nil, nil, fmt.Errorf("audit envelope MAC mismatch")
	}
	return prevMAC, mac, nil
}

func payloadMACBytes(payload envelopePayload) []byte {
	if payload.encoding == payloadEncodingAge {
		return payload.ciphertext
	}
	return payload.plain
}

func computeEnvelopeMAC(key []byte, env auditEnvelope, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	writeMACField(mac, envelopeMACDomain)
	writeMACField(mac, []byte(env.APIVersion))
	writeMACField(mac, []byte(env.Kind))
	writeMACField(mac, []byte(env.KeyID))
	writeMACUint64(mac, env.Sequence)
	writeMACField(mac, []byte(env.PrevMAC))
	writeMACField(mac, []byte(env.PayloadEncoding))
	writeMACField(mac, payload)
	return mac.Sum(nil)
}

func computeCheckpointMAC(key []byte, checkpoint auditCheckpoint) []byte {
	mac := hmac.New(sha256.New, key)
	writeMACField(mac, checkpointMACDomain)
	writeMACField(mac, []byte(checkpoint.APIVersion))
	writeMACField(mac, []byte(checkpoint.Kind))
	writeMACField(mac, []byte(checkpoint.KeyID))
	writeMACUint64(mac, checkpoint.BaseSequence)
	writeMACField(mac, []byte(checkpoint.BaseMAC))
	writeMACUint64(mac, checkpoint.HeadSequence)
	writeMACField(mac, []byte(checkpoint.HeadMAC))
	return mac.Sum(nil)
}

func writeMACField(mac hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write(value)
}

func writeMACUint64(mac hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeMACField(mac, encoded[:])
}

func encodeMAC(mac []byte) string {
	if len(mac) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(mac)
}

func decodeMAC(encoded string, allowEmpty bool) ([]byte, error) {
	if encoded == "" && allowEmpty {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded || len(decoded) != macSize {
		return nil, fmt.Errorf("expected a canonical %d-byte MAC", macSize)
	}
	return decoded, nil
}

func decodeSequenceMAC(encoded string, sequence uint64) ([]byte, error) {
	if sequence == 0 {
		if encoded != "" {
			return nil, fmt.Errorf("sequence zero must use an empty MAC")
		}
		return nil, nil
	}
	return decodeMAC(encoded, false)
}

func makeCheckpoint(key []byte, baseSequence uint64, baseMAC []byte, headSequence uint64, headMAC []byte) auditCheckpoint {
	checkpoint := auditCheckpoint{
		APIVersion:   checkpointAPIVersion,
		Kind:         checkpointKind,
		KeyID:        integrityKeyID(key),
		BaseSequence: baseSequence,
		BaseMAC:      encodeMAC(baseMAC),
		HeadSequence: headSequence,
		HeadMAC:      encodeMAC(headMAC),
	}
	checkpoint.MAC = encodeMAC(computeCheckpointMAC(key, checkpoint))
	return checkpoint
}

func loadCheckpoint(path string, key []byte) (auditCheckpoint, bool, error) {
	path = checkpointPath(path)
	data, err := readBoundedOwnerOnlyArtifact(path, maxCheckpointFileBytes, "audit checkpoint")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return auditCheckpoint{}, false, nil
		}
		return auditCheckpoint{}, false, err
	}
	var checkpoint auditCheckpoint
	if err := strictDecodeObject(data, &checkpoint); err != nil {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint", err)
	}
	if checkpoint.APIVersion != checkpointAPIVersion || checkpoint.Kind != checkpointKind {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "unsupported audit checkpoint", nil)
	}
	if checkpoint.KeyID != integrityKeyID(key) {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "audit checkpoint key ID mismatch", nil)
	}
	baseMAC, err := decodeSequenceMAC(checkpoint.BaseMAC, checkpoint.BaseSequence)
	if err != nil {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint base MAC", err)
	}
	headMAC, err := decodeSequenceMAC(checkpoint.HeadMAC, checkpoint.HeadSequence)
	if err != nil {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint head MAC", err)
	}
	if checkpoint.HeadSequence < checkpoint.BaseSequence {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "audit checkpoint head precedes base", nil)
	}
	if checkpoint.BaseSequence == checkpoint.HeadSequence && !hmac.Equal(baseMAC, headMAC) {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "audit checkpoint base/head MAC mismatch", nil)
	}
	mac, err := decodeMAC(checkpoint.MAC, false)
	if err != nil {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint MAC", err)
	}
	expected := computeCheckpointMAC(key, checkpoint)
	if !hmac.Equal(mac, expected) {
		return auditCheckpoint{}, true, apperrors.New(apperrors.CodeValidationFailed, "audit checkpoint MAC mismatch", nil)
	}
	return checkpoint, true, nil
}

func checkpointBase(checkpoint auditCheckpoint) (uint64, []byte, error) {
	mac, err := decodeSequenceMAC(checkpoint.BaseMAC, checkpoint.BaseSequence)
	return checkpoint.BaseSequence, mac, err
}

func checkpointHead(checkpoint auditCheckpoint) (uint64, []byte, error) {
	mac, err := decodeSequenceMAC(checkpoint.HeadMAC, checkpoint.HeadSequence)
	return checkpoint.HeadSequence, mac, err
}

func writeCheckpoint(path string, checkpoint auditCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit checkpoint", err)
	}
	target := checkpointPath(path)
	if err := ensureOwnerOnlyDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	file, tempPath, err := createOwnerOnlyTemp(filepath.Dir(target), filepath.Base(target)+".tmp-")
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create audit checkpoint temp file", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}()
	if err := verifyOwnerOnlyFile(tempPath); err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write audit checkpoint", err)
	}
	if err := file.Sync(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit checkpoint", err)
	}
	if err := file.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close audit checkpoint", err)
	}
	if err := replaceFile(tempPath, target); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to replace audit checkpoint", err)
	}
	if err := secureOwnerOnlyFile(target); err != nil {
		return err
	}
	return nil
}

func nextSequence(head uint64) (uint64, error) {
	if head == math.MaxUint64 {
		return 0, apperrors.New(apperrors.CodeConflict, "audit sequence exhausted", nil)
	}
	return head + 1, nil
}

func readBoundedOwnerOnlyArtifact(path string, limit int64, label string) ([]byte, error) {
	file, err := openAuditReadFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to stat "+label, err)
	}
	if info.Size() > limit {
		return nil, apperrors.New(apperrors.CodeValidationFailed, label+" exceeds the maximum supported size", nil)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read "+label, err)
	}
	if int64(len(data)) > limit {
		return nil, apperrors.New(apperrors.CodeValidationFailed, label+" exceeds the maximum supported size", nil)
	}
	return data, nil
}

func looksLikeEnvelope(data []byte) bool {
	if !json.Valid(data) {
		return bytes.Contains(data, []byte(envelopeAPIVersion)) &&
			bytes.Contains(data, []byte(envelopeKind))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return false
	}
	fields := make([]string, 0, 7)
	var hasAPIVersion, hasKind bool
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		if tokenErr != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok {
			return false
		}
		var value json.RawMessage
		if decodeErr := decoder.Decode(&value); decodeErr != nil {
			return false
		}
		fields = append(fields, key)
		var text string
		switch {
		case strings.EqualFold(key, "apiVersion"):
			if json.Unmarshal(value, &text) == nil && text == envelopeAPIVersion {
				hasAPIVersion = true
			}
		case strings.EqualFold(key, "kind"):
			if json.Unmarshal(value, &text) == nil && text == envelopeKind {
				hasKind = true
			}
		}
	}
	if hasAPIVersion && hasKind {
		return true
	}
	for _, field := range []string{"keyId", "sequence", "payloadEncoding", "payload", "mac"} {
		if _, exists := equalFoldJSONField(fields, field); !exists {
			return false
		}
	}
	return true
}

func strictDecodeObject(data []byte, target any) error {
	if err := rejectDuplicateTopLevelKeys(data, target); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateTopLevelKeys(data []byte, target any) error {
	canonical, err := canonicalJSONFieldNames(target)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("expected JSON object")
	}
	seen := make([]string, 0, len(canonical))
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("expected JSON object key")
		}
		if previous, exists := equalFoldJSONField(seen, key); exists {
			return fmt.Errorf("semantically duplicate JSON keys %q and %q", previous, key)
		}
		seen = append(seen, key)
		if expected, exists := equalFoldJSONField(canonical, key); exists && key != expected {
			return fmt.Errorf("non-canonical JSON key %q; expected %q", key, expected)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func canonicalJSONFieldNames(target any) ([]string, error) {
	valueType := reflect.TypeOf(target)
	if valueType == nil {
		return nil, fmt.Errorf("nil JSON target")
	}
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("strict JSON target must be a struct")
	}
	fields := make([]string, 0, valueType.NumField())
	for index := range valueType.NumField() {
		field := valueType.Field(index)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" {
			tag = field.Name
		}
		if tag == "-" {
			continue
		}
		fields = append(fields, tag)
	}
	return fields, nil
}

func equalFoldJSONField(fields []string, candidate string) (string, bool) {
	for _, field := range fields {
		if strings.EqualFold(field, candidate) {
			return field, true
		}
	}
	return "", false
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unexpected trailing JSON value")
}
