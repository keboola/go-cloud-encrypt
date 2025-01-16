package cloudencrypt

import (
	"bytes"
	"context"
	"fmt"
)

// PrefixEncryptor adds the given prefix to the encrypted value.
type PrefixEncryptor struct {
	encryptor Encryptor
	prefix    []byte
}

func NewPrefixEncryptor(encryptor Encryptor, prefix []byte) (*PrefixEncryptor, error) {
	return &PrefixEncryptor{
		encryptor: encryptor,
		prefix:    prefix,
	}, nil
}

func (encryptor *PrefixEncryptor) Prefix() []byte {
	return encryptor.prefix
}

func (encryptor *PrefixEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	return append(encryptor.prefix, encryptedValue...), nil
}

func (encryptor *PrefixEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	if !bytes.Equal(encryptor.prefix, ciphertext[0:len(encryptor.prefix)]) {
		return nil, fmt.Errorf(`encrypted value doesn't have the expected prefix "%s"`, encryptor.prefix)
	}

	return encryptor.encryptor.Decrypt(ctx, ciphertext[len(encryptor.prefix):], metadata)
}

func (encryptor *PrefixEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
