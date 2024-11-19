package cloudencrypt

import (
	"context"
)

type Metadata map[string]string

type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error)
	Close() error
}
