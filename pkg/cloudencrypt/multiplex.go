package cloudencrypt

import (
	"bytes"
	"context"
	"fmt"
)

// MultiplexEncryptor encrypts values using the main encryptor but is able to decode
// using other encryptors as well based on the prefix of the given encrypted value.
type MultiplexEncryptor struct {
	encryptor  *PrefixEncryptor
	decryptors []*PrefixEncryptor
}

func NewMultiplexEncryptor(ctx context.Context, encryptor *PrefixEncryptor, decryptors []*PrefixEncryptor) (*MultiplexEncryptor, error) {
	return &MultiplexEncryptor{
		encryptor:  encryptor,
		decryptors: append(decryptors, encryptor),
	}, nil
}

func (encryptor *MultiplexEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	return encryptor.encryptor.Encrypt(ctx, plaintext, metadata)
}

func (encryptor *MultiplexEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	for _, decryptor := range encryptor.decryptors {
		if bytes.Equal(decryptor.Prefix(), ciphertext[0:len(decryptor.Prefix())]) {
			return decryptor.Decrypt(ctx, ciphertext, metadata)
		}
	}

	return nil, fmt.Errorf(`no encryptor found for the given encrypted value`)
}

func (encryptor *MultiplexEncryptor) Close() error {
	for _, prefixEncryptor := range encryptor.decryptors {
		if err := prefixEncryptor.Close(); err != nil {
			return err
		}
	}
	return nil
}
