package cloudencrypt

import (
	"context"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/internal/serialize"
)

const (
	mapKeySecretKey  = "secretKey"
	mapKeyCipherText = "ciphertext"
)

// AESWrapEncryptor implements Encryptor by encrypting the value using the AESEncryptor
// and then encrypting the secret key using the provided encryptor.
type AESWrapEncryptor struct {
	encryptor Encryptor
}

func NewAESWrapEncryptor(ctx context.Context, encryptor Encryptor) (*AESWrapEncryptor, error) {
	return &AESWrapEncryptor{
		encryptor: encryptor,
	}, nil
}

func (encryptor *AESWrapEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	// Generate a random secret key
	secretKey, err := random.SecretKey()
	if err != nil {
		return nil, err
	}

	ciphertext, err := aesEncrypt(ctx, secretKey, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	// Encrypt the secret key
	encryptedSecretKey, err := encryptor.encryptor.Encrypt(ctx, secretKey, metadata)
	if err != nil {
		return nil, err
	}

	output := make(map[string][]byte)
	output[mapKeySecretKey] = encryptedSecretKey
	output[mapKeyCipherText] = ciphertext

	encoded, err := serialize.Serialize(output)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func (encryptor *AESWrapEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	decoded, err := serialize.Deserialize[map[string][]byte](ciphertext)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret key
	secretKey, err := encryptor.encryptor.Decrypt(ctx, decoded[mapKeySecretKey], metadata)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesDecrypt(ctx, secretKey, decoded[mapKeyCipherText], metadata)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (encryptor *AESWrapEncryptor) Close() error {
	return encryptor.encryptor.Close()
}

func aesEncrypt(ctx context.Context, secretKey []byte, plaintext []byte, metadata Metadata) ([]byte, error) {
	aesEncryptor, err := NewAESEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer aesEncryptor.Close()

	// Encrypt given plaintext using the random secret key
	ciphertext, err := aesEncryptor.Encrypt(ctx, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func aesDecrypt(ctx context.Context, secretKey []byte, ciphertext []byte, metadata Metadata) ([]byte, error) {
	// Decrypt the value using the decrypted secret key
	aesEncryptor, err := NewAESEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer aesEncryptor.Close()

	plaintext, err := aesEncryptor.Decrypt(ctx, ciphertext, metadata)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
