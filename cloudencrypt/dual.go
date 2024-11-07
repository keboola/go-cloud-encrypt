package cloudencrypt

import (
	"context"
)

const (
	mapKeyEncryptedKey   = "key"
	mapKeyEncryptedValue = "value"
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

func (encryptor *DualEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	// Generate a random secret key
	secretKey, err := generateSecretKey()
	if err != nil {
		return nil, err
	}

	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer nativeEncryptor.Close()

	// Encrypt the value using the random secret key
	encryptedValue, err := nativeEncryptor.Encrypt(ctx, value, metadata...)
	if err != nil {
		return nil, err
	}

	// Encrypt the secret key
	encryptedSecretKey, err := encryptor.encryptor.Encrypt(ctx, secretKey, metadata...)
	if err != nil {
		return nil, err
	}

	output := make(map[string]string)
	output[mapKeyEncryptedKey] = string(encryptedSecretKey)
	output[mapKeyEncryptedValue] = string(encryptedValue)

	encoded, err := encode(output)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func (encryptor *DualEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	decoded, err := decode(encryptedValue)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret key
	secretKey, err := encryptor.encryptor.Decrypt(ctx, []byte(decoded[mapKeyEncryptedKey]), metadata...)
	if err != nil {
		return nil, err
	}

	// Decrypt the value using the decrypted secret key
	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	if err != nil {
		return nil, err
	}

	defer nativeEncryptor.Close()

	decrypted, err := nativeEncryptor.Decrypt(ctx, []byte(decoded[mapKeyEncryptedValue]), metadata...)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func (encryptor *DualEncryptor) Close() error {
	return encryptor.encryptor.Close()
}

func generateSecretKey() ([]byte, error) {
	return randomBytes(32)
}
