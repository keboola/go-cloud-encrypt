package cloudencrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"

	"github.com/pkg/errors"
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

func (encryptor *NativeEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	additionalData, err := encode(buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(encryptor.gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Passing nonce as the first parameter prepends it to the actual encrypted value.
	return encryptor.gcm.Seal(nonce, nonce, value, additionalData), nil
}

func (encryptor *NativeEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	additionalData, err := encode(buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	nonceSize := encryptor.gcm.NonceSize()
	// Split the encrypted value back to the nonce + actual encrypted value.
	nonce, ciphertext := encryptedValue[:nonceSize], encryptedValue[nonceSize:]

	decryptedValue, err := encryptor.gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.Wrapf(err, "gcm decryption failed: %s", err.Error())
	}

	return decryptedValue, nil
}

func (encryptor *NativeEncryptor) Close() error {
	return nil
}