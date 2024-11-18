package cloudencrypt

import (
	"context"
	"crypto/rand"

	"github.com/pkg/errors"
)

type Metadata map[string]string

type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error)
	Close() error
}

func randomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "can't generate random bytes: %s", err.Error())
	}

	return bytes, err
}
