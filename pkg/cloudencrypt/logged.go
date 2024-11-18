package cloudencrypt

import (
	"context"
	"log"
)

// LoggedEncryptor wraps another Encryptor and adds logging.
type LoggedEncryptor struct {
	encryptor Encryptor
	logger    *log.Logger
}

func NewLoggedEncryptor(ctx context.Context, encryptor Encryptor, logger *log.Logger) (*LoggedEncryptor, error) {
	return &LoggedEncryptor{
		encryptor: encryptor,
		logger:    logger,
	}, nil
}

func (encryptor *LoggedEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata ...MetadataKV) ([]byte, error) {
	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, plaintext, metadata...)
	if err != nil {
		encryptor.logger.Printf("encryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("encryption success")

	return encryptedValue, nil
}

func (encryptor *LoggedEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata ...MetadataKV) ([]byte, error) {
	plaintext, err := encryptor.encryptor.Decrypt(ctx, ciphertext, metadata...)
	if err != nil {
		encryptor.logger.Printf("decryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("decryption success")

	return plaintext, nil
}

func (encryptor *LoggedEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
