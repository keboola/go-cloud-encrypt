package cloudencrypt

import (
	"context"
	"crypto/rand"

	"github.com/pkg/errors"
)

type Encryptor interface {
	Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error)
	Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error)
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
