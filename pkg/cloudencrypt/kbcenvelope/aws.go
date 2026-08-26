package kbcenvelope

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// AWSEncryptor implements cloudencrypt.Encryptor for the KBC:: envelope wrapped by AWS KMS.
// Decrypt reproduces PHP keboola/object-encryptor's AWS path: unwrap the per-value key via
// KMS Decrypt (encryption context = metadata), then Defuse-decrypt the payload with it.
type AWSEncryptor struct {
	client KMSClient
	keyID  string
}

// NewAWSEncryptor returns an AWSEncryptor. keyID is the AWS KMS key ID used to unwrap values.
func NewAWSEncryptor(client KMSClient, keyID string) *AWSEncryptor {
	return &AWSEncryptor{client: client, keyID: keyID}
}

func (e *AWSEncryptor) Encrypt(_ context.Context, _ []byte, _ cloudencrypt.Metadata) ([]byte, error) {
	return nil, ErrEncryptNotImplemented
}

func (e *AWSEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata cloudencrypt.Metadata) ([]byte, error) {
	envelope, err := DecodeAWSEnvelope(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher text: %w", err)
	}

	decryptOutput, err := e.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    envelope.EncryptedKey,
		KeyId:             &e.keyID,
		EncryptionContext: metadata,
	})
	if err != nil {
		return nil, &BackendError{Cause: fmt.Errorf("KMS decrypt failed: %w", err)}
	}

	plaintext, err := decryptDefuse(envelope.EncryptedPayload, decryptOutput.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

func (e *AWSEncryptor) Close() error {
	return nil
}
