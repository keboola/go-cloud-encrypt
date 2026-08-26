package kbcenvelope

import (
	"context"
	"errors"
	"fmt"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// AzureEncryptor implements cloudencrypt.Encryptor for the KBC:: envelope wrapped by Azure Key
// Vault. Unlike AWS/GCP, the per-value key isn't wrapped by a KMS call: the cipher text embeds
// the name of a Key Vault *secret* that itself holds a Defuse Key plus the encryption-context
// metadata it was created for. Decrypt fetches that secret (always the latest version — see
// below), verifies the caller's metadata is a subset of what's stored on it, then
// Defuse-decrypts the payload.
type AzureEncryptor struct {
	client AKVClient
}

// NewAzureEncryptor returns an AzureEncryptor backed by an Azure Key Vault secrets client.
func NewAzureEncryptor(client AKVClient) *AzureEncryptor {
	return &AzureEncryptor{client: client}
}

func (e *AzureEncryptor) Encrypt(_ context.Context, _ []byte, _ cloudencrypt.Metadata) ([]byte, error) {
	return nil, ErrEncryptNotImplemented
}

func (e *AzureEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata cloudencrypt.Metadata) ([]byte, error) {
	envelope, err := DecodeAzureEnvelope(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher text: %w", err)
	}

	// The cipher text carries a secret version, but the secret is always fetched at its latest
	// version — PHP's object-encryptor never pins to the embedded one, since the metadata
	// verification below is what actually authenticates the value, not the version pointer.
	secretResp, err := e.client.GetSecret(ctx, envelope.SecretName, "", nil)
	if err != nil {
		return nil, &BackendError{Cause: fmt.Errorf("failed to get secret from Key Vault: %w", err)}
	}

	if secretResp.Value == nil {
		return nil, errors.New("secret value is nil")
	}

	secretData, err := decodeAzureSecret(*secretResp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Azure secret: %w", err)
	}

	if err := verifyMetadataSubset(secretData.Metadata, metadata); err != nil {
		return nil, fmt.Errorf("encryption context mismatch: %w", err)
	}

	plaintext, err := decryptDefuse(envelope.EncryptedPayload, secretData.Key)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

func (e *AzureEncryptor) Close() error {
	return nil
}

// verifyMetadataSubset checks that every key in expected exists in stored with the same value.
// stored may carry additional keys the caller didn't ask about — PHP's object-encryptor only
// verifies the keys it expects, it doesn't require an exact match on the full key set.
func verifyMetadataSubset(stored map[string]string, expected cloudencrypt.Metadata) error {
	for key, expectedValue := range expected {
		actualValue, ok := stored[key]
		if !ok {
			return fmt.Errorf("missing metadata key %s", key)
		}

		if actualValue != expectedValue {
			return fmt.Errorf("metadata %s mismatch: expected %s, got %s", key, expectedValue, actualValue)
		}
	}

	return nil
}
