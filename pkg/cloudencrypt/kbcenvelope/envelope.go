package kbcenvelope

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/elliotchance/phpserialize"
)

// maxDecompressedSize caps how much a cipher text may inflate to. Cipher texts are a few
// kilobytes; the cap exists because the compressed form is attacker-controlled (it arrives in
// a user's configuration) and zlib will happily expand a few kilobytes into hundreds of
// megabytes in the calling process.
const maxDecompressedSize = 1 << 20 // 1 MiB

// Envelope is the decoded [payload, key/secret-ref] envelope, before the payload's own
// Defuse decryption.
type Envelope struct {
	EncryptedPayload []byte
	EncryptedKey     []byte // AWS / Google
	SecretName       string // Azure
	SecretVersion    string // Azure; decoded but deliberately unused, see azure.go
}

// readBounded reads r to completion, refusing to buffer more than maxDecompressedSize.
func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
	if err != nil {
		return nil, err
	}

	if len(data) > maxDecompressedSize {
		return nil, fmt.Errorf("decompressed data exceeds the %d byte limit", maxDecompressedSize)
	}

	return data, nil
}

// decodePHPArray zlib-decompresses raw (PHP's gzcompress() output — zlib format, not gzip) and
// PHP-deserializes the result into a numeric-indexed array. raw is the envelope payload after
// the "KBC::...::" prefix and its base64 layer have both already been stripped by the caller.
func decodePHPArray(raw []byte) (map[any]any, error) {
	zlibReader, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("zlib decompress failed: %w", err)
	}
	defer zlibReader.Close()

	serialized, err := readBounded(zlibReader)
	if err != nil {
		return nil, fmt.Errorf("zlib read failed: %w", err)
	}

	result, err := manualPHPDeserializeArray(serialized)
	if err != nil {
		return nil, fmt.Errorf("php deserialize failed: %w", err)
	}

	return result, nil
}

func bytesAt(m map[any]any, index int64) ([]byte, error) {
	value, ok := m[index]
	if !ok {
		return nil, fmt.Errorf("missing index %d in cipher data", index)
	}

	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("invalid value type at index %d: %T", index, value)
	}
}

func stringAt(m map[any]any, index int64) (string, error) {
	value, ok := m[index]
	if !ok {
		return "", fmt.Errorf("missing index %d in cipher data", index)
	}

	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid value type at index %d: %T", index, value)
	}

	return s, nil
}

// DecodeAWSEnvelope decodes an AWS KMS envelope: [0 => encryptedPayload, 1 => encryptedKey].
func DecodeAWSEnvelope(raw []byte) (*Envelope, error) {
	m, err := decodePHPArray(raw)
	if err != nil {
		return nil, err
	}

	payload, err := bytesAt(m, 0)
	if err != nil {
		return nil, err
	}

	key, err := bytesAt(m, 1)
	if err != nil {
		return nil, err
	}

	return &Envelope{EncryptedPayload: payload, EncryptedKey: key}, nil
}

// DecodeGCPEnvelope decodes a Google Cloud KMS envelope: [0 => encryptedKey, 1 => encryptedPayload].
func DecodeGCPEnvelope(raw []byte) (*Envelope, error) {
	m, err := decodePHPArray(raw)
	if err != nil {
		return nil, err
	}

	key, err := bytesAt(m, 0)
	if err != nil {
		return nil, err
	}

	payload, err := bytesAt(m, 1)
	if err != nil {
		return nil, err
	}

	return &Envelope{EncryptedPayload: payload, EncryptedKey: key}, nil
}

// DecodeAzureEnvelope decodes an Azure Key Vault envelope:
// [2 => encryptedPayload, 3 => secretName, 4 => secretVersion].
func DecodeAzureEnvelope(raw []byte) (*Envelope, error) {
	m, err := decodePHPArray(raw)
	if err != nil {
		return nil, err
	}

	payload, err := bytesAt(m, 2)
	if err != nil {
		return nil, err
	}

	secretName, err := stringAt(m, 3)
	if err != nil {
		return nil, err
	}

	secretVersion, err := stringAt(m, 4)
	if err != nil {
		return nil, err
	}

	return &Envelope{EncryptedPayload: payload, SecretName: secretName, SecretVersion: secretVersion}, nil
}

// azureSecretData is the decoded content of an Azure Key Vault secret used by kbcenvelope:
// a [metadata, Defuse Key] pair, PHP-serialized and gzcompress()ed by the producer.
type azureSecretData struct {
	Metadata map[string]string
	Key      []byte
}

// decodeAzureSecret decodes an Azure Key Vault secret value: base64(gzcompress(serialize([metadata, key]))),
// where metadata is at index 0 and the Defuse Key (ASCII hex string) is at index 1. This is a
// second, independent PHP-serialized blob — distinct from the outer cipher-text envelope — so
// it does its own base64/zlib decode.
func decodeAzureSecret(encodedSecret string) (*azureSecretData, error) {
	compressed, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	zlibReader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("zlib decompress failed: %w", err)
	}
	defer zlibReader.Close()

	serialized, err := readBounded(zlibReader)
	if err != nil {
		return nil, fmt.Errorf("zlib read failed: %w", err)
	}

	// This blob's members are short ASCII text (metadata values, a hex-encoded key), not the
	// large binary-safe strings the outer envelope carries, so the general-purpose library is
	// fine here rather than the manual deserializer.
	result, err := phpserialize.UnmarshalAssociativeArray(serialized)
	if err != nil {
		return nil, fmt.Errorf("php deserialize failed: %w", err)
	}

	metadata0, has0 := result[int64(0)]
	if !has0 {
		return nil, errors.New("missing index 0 (metadata) in Azure secret")
	}

	metadataMap, err := convertToStringMap(metadata0)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata format: %w", err)
	}

	key1, has1 := result[int64(1)]
	if !has1 {
		return nil, errors.New("missing index 1 (key) in Azure secret")
	}

	keyString, ok := key1.(string)
	if !ok {
		return nil, fmt.Errorf("key at index 1 is not a string: %T", key1)
	}

	keyBytes, err := decodeDefuseKey(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Defuse Key: %w", err)
	}

	return &azureSecretData{Metadata: metadataMap, Key: keyBytes}, nil
}

// convertToStringMap converts a deserialized PHP array to map[string]string. An empty PHP
// array deserializes as []any rather than a map, so that shape is handled explicitly.
func convertToStringMap(data any) (map[string]string, error) {
	switch v := data.(type) {
	case []any:
		return convertEmptyPHPArray(v)
	case map[any]any:
		return convertAnyKeyedPHPMap(v)
	case map[string]any:
		return convertStringKeyedPHPMap(v)
	default:
		return nil, fmt.Errorf("unexpected type: %T", data)
	}
}

// convertEmptyPHPArray handles PHP's empty-array literal, which the deserializer represents as
// []any regardless of whether the source was semantically a list or a map.
func convertEmptyPHPArray(v []any) (map[string]string, error) {
	if len(v) == 0 {
		return make(map[string]string), nil
	}

	return nil, errors.New("non-empty array cannot be converted to map")
}

func convertAnyKeyedPHPMap(v map[any]any) (map[string]string, error) {
	result := make(map[string]string, len(v))

	for k, val := range v {
		keyStr, err := phpArrayKeyToString(k)
		if err != nil {
			return nil, err
		}

		valStr, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value type for key %v: %T", k, val)
		}

		result[keyStr] = valStr
	}

	return result, nil
}

func convertStringKeyedPHPMap(v map[string]any) (map[string]string, error) {
	result := make(map[string]string, len(v))

	for k, val := range v {
		valStr, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value type for key %s: %T", k, val)
		}

		result[k] = valStr
	}

	return result, nil
}

// phpArrayKeyToString normalizes a PHP array key (string or, for numeric keys, int64) to string.
func phpArrayKeyToString(k any) (string, error) {
	switch kt := k.(type) {
	case string:
		return kt, nil
	case int64:
		return strconv.FormatInt(kt, 10), nil
	default:
		return "", fmt.Errorf("invalid key type: %T", k)
	}
}
