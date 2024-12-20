package cloudencrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"

	"github.com/pkg/errors"

	"github.com/keboola/go-cloud-encrypt/internal/metadata"
	"github.com/keboola/go-cloud-encrypt/internal/random"
)

// NativeEncryptor Implements Encryptor without using any cloud service.
type NativeEncryptor struct {
	gcm cipher.AEAD
}

func NewNativeEncryptor(secretKey []byte) (*NativeEncryptor, error) {
	aesCipher, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, errors.Wrapf(err, "can't create aes cipher: %s", err.Error())
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrapf(err, "can't create gcm: %s", err.Error())
	}

	return &NativeEncryptor{
		gcm: gcm,
	}, nil
}

func (encryptor *NativeEncryptor) Encrypt(ctx context.Context, plaintext []byte, meta Metadata) ([]byte, error) {
	additionalData, err := metadata.Encode(meta)
	if err != nil {
		return nil, err
	}

	nonce, err := random.Bytes(encryptor.gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Passing nonce as the first parameter prepends it to the actual encrypted value.
	return encryptor.gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (encryptor *NativeEncryptor) Decrypt(ctx context.Context, ciphertext []byte, meta Metadata) ([]byte, error) {
	additionalData, err := metadata.Encode(meta)
	if err != nil {
		return nil, err
	}

	nonceSize := encryptor.gcm.NonceSize()
	// Split the ciphertext back to the nonce + actual ciphertext.
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := encryptor.gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.Wrapf(err, "gcm decryption failed: %s", err.Error())
	}

	return plaintext, nil
}

func (encryptor *NativeEncryptor) Close() error {
	return nil
}
