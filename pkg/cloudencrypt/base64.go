package cloudencrypt

import (
	"context"
	"encoding/base64"
)

// Base64Encryptor wraps a given encryptor and applies base64 encoding to the encrypted value.
type Base64Encryptor struct {
	encryptor Encryptor
}

func NewBase64Encryptor(encryptor Encryptor) (*Base64Encryptor, error) {
	return &Base64Encryptor{encryptor: encryptor}, nil
}

func (encryptor *Base64Encryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	ciphertext, err := encryptor.encryptor.Encrypt(ctx, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(dst, ciphertext)

	return dst, nil
}

func (encryptor *Base64Encryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	if _, err := base64.StdEncoding.Decode(dst, ciphertext); err != nil {
		return nil, err
	}

	plaintext, err := encryptor.encryptor.Decrypt(ctx, dst, metadata)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (encryptor *Base64Encryptor) Close() error {
	return encryptor.encryptor.Close()
}
