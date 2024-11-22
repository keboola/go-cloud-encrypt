package cloudencrypt

import (
	"context"

	"github.com/keboola/go-cloud-encrypt/internal/encode"
)

type GenericEncryptor[T any] struct {
	encryptor Encryptor
}

func NewGenericEncryptor[T any](encryptor Encryptor) GenericEncryptor[T] {
	return GenericEncryptor[T]{encryptor}
}

func (encryptor *GenericEncryptor[T]) Encrypt(ctx context.Context, data T, metadata Metadata) ([]byte, error) {
	plaintext, err := encode.Encode(data)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encryptor.encryptor.Encrypt(ctx, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (encryptor *GenericEncryptor[T]) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) (result T, err error) {
	plaintext, err := encryptor.encryptor.Decrypt(ctx, ciphertext, metadata)
	if err != nil {
		return result, err
	}

	result, err = encode.Decode[T](plaintext)
	if err != nil {
		return result, err
	}

	return result, nil
}
