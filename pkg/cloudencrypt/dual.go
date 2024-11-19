package cloudencrypt

import (
	"context"

	"github.com/keboola/go-cloud-encrypt/internal/encode"
	"github.com/keboola/go-cloud-encrypt/internal/random"
)

const (
	mapKeySecretKey  = "secretKey"
	mapKeyCipherText = "ciphertext"
)

// DualEncryptor implements Encryptor by encrypting the value using the NativeEncryptor
// and then encrypting the secret key using the provided encryptor.
type DualEncryptor struct {
	encryptor Encryptor
}

func NewDualEncryptor(ctx context.Context, encryptor Encryptor) (*DualEncryptor, error) {
	return &DualEncryptor{
		encryptor: encryptor,
	}, nil
}

func (encryptor *DualEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	// Generate a random secret key
	secretKey, err := random.SecretKey()
	if err != nil {
		return nil, err
	}

	ciphertext, err := nativeEncrypt(ctx, secretKey, plaintext, metadata)
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

	encoded, err := encode.Encode(output)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func (encryptor *DualEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	decoded, err := encode.Decode[map[string][]byte](ciphertext)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret key
	secretKey, err := encryptor.encryptor.Decrypt(ctx, decoded[mapKeySecretKey], metadata)
	if err != nil {
		return nil, err
	}

	plaintext, err := nativeDecrypt(ctx, secretKey, decoded[mapKeyCipherText], metadata)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (encryptor *DualEncryptor) Close() error {
	return encryptor.encryptor.Close()
}

func nativeEncrypt(ctx context.Context, secretKey []byte, plaintext []byte, metadata Metadata) ([]byte, error) {
	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer nativeEncryptor.Close()

	// Encrypt given plaintext using the random secret key
	ciphertext, err := nativeEncryptor.Encrypt(ctx, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func nativeDecrypt(ctx context.Context, secretKey []byte, ciphertext []byte, metadata Metadata) ([]byte, error) {
	// Decrypt the value using the decrypted secret key
	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer nativeEncryptor.Close()

	plaintext, err := nativeEncryptor.Decrypt(ctx, ciphertext, metadata)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
