package kbcenvelope

import (
	"context"
	"encoding/base64"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// GCPEncryptor implements cloudencrypt.Encryptor for the KBC:: envelope wrapped by Google
// Cloud KMS. The per-value key is unwrapped via a KMS Decrypt call whose Additional
// Authenticated Data is the metadata, PHP-serialized and gzcompress()ed exactly as the PHP
// producer computed it — see googleAAD and zlib_cgo.go for why that has to be byte-exact.
type GCPEncryptor struct {
	client  GKMSClient
	keyName string
}

// NewGCPEncryptor returns a GCPEncryptor. keyName is the full Google Cloud KMS key resource name.
func NewGCPEncryptor(client GKMSClient, keyName string) *GCPEncryptor {
	return &GCPEncryptor{client: client, keyName: keyName}
}

func (e *GCPEncryptor) Encrypt(_ context.Context, _ []byte, _ cloudencrypt.Metadata) ([]byte, error) {
	return nil, ErrEncryptNotImplemented
}

func (e *GCPEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata cloudencrypt.Metadata) ([]byte, error) {
	envelope, err := DecodeGCPEnvelope(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher text: %w", err)
	}

	aad, err := googleAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to build AAD: %w", err)
	}

	decryptResp, err := e.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        e.keyName,
		Ciphertext:                  envelope.EncryptedKey,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		return nil, &BackendError{Cause: fmt.Errorf("GKMS decrypt failed: %w", err)}
	}

	// Google KMS returns a Defuse Key in its ASCII-safe hex string format, not raw bytes.
	keyBytes, err := decodeDefuseKey(string(decryptResp.GetPlaintext()))
	if err != nil {
		return nil, fmt.Errorf("failed to decode Defuse Key: %w", err)
	}

	plaintext, err := decryptDefuse(envelope.EncryptedPayload, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return plaintext, nil
}

func (e *GCPEncryptor) Close() error {
	return nil
}

// googleAAD builds the Additional Authenticated Data PHP's object-encryptor sends to Google
// KMS: base64(gzcompress(phpserialize(sorted metadata))). It must match the encrypting side's
// bytes exactly or KMS rejects the AAD — see zlibCompressPHPCompatible for why that requires CGO.
func googleAAD(metadata cloudencrypt.Metadata) ([]byte, error) {
	serialized := phpSerializeSortedMetadata(metadata)

	compressed, err := zlibCompressPHPCompatible(serialized)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(compressed)))
	base64.StdEncoding.Encode(encoded, compressed)

	return encoded, nil
}
