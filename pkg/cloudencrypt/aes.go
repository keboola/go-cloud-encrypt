package cloudencrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/keboola/go-cloud-encrypt/internal/random"
)

// AESEncryptor Implements Encryptor without using any cloud service.
type AESEncryptor struct {
	gcm       cipher.AEAD
	generator NonceGenerator
}

type NonceGenerator func(int) ([]byte, error)

func NewAESEncryptor(secretKey []byte) (*AESEncryptor, error) {
	return NewAESEncryptorWithNonceGenerator(secretKey, random.Bytes)
}

func NewAESEncryptorWithNonceGenerator(secretKey []byte, generator NonceGenerator) (*AESEncryptor, error) {
	if generator == nil {
		return nil, errors.New("missing nonce generator")
	}

	aesCipher, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, errors.Wrapf(err, "can't create aes cipher: %s", err.Error())
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrapf(err, "can't create gcm: %s", err.Error())
	}

	return &AESEncryptor{
		gcm:       gcm,
		generator: generator,
	}, nil
}

func (encryptor *AESEncryptor) Encrypt(ctx context.Context, plaintext []byte, meta Metadata) ([]byte, error) {
	additionalData, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}

	nonce, err := encryptor.generator(encryptor.gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Passing nonce as the first parameter prepends it to the actual encrypted value.
	return encryptor.gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (encryptor *AESEncryptor) Decrypt(ctx context.Context, ciphertext []byte, meta Metadata) ([]byte, error) {
	additionalData, err := json.Marshal(meta)
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

func (encryptor *AESEncryptor) Close() error {
	return nil
}
