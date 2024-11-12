package cloudencrypt

import (
	"context"
	"log"
)

// LogEncryptor wraps another Encryptor and adds logging.
type LogEncryptor struct {
	encryptor Encryptor
	logger    *log.Logger
}

func NewLogEncryptor(ctx context.Context, encryptor Encryptor, logger *log.Logger) (*LogEncryptor, error) {
	return &LogEncryptor{
		encryptor: encryptor,
		logger:    logger,
	}, nil
}

func (encryptor *LogEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata ...MetadataKV) ([]byte, error) {
	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, plaintext, metadata...)
	if err != nil {
		encryptor.logger.Printf("encryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("encryption success")

	return encryptedValue, nil
}

func (encryptor *LogEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata ...MetadataKV) ([]byte, error) {
	plaintext, err := encryptor.encryptor.Decrypt(ctx, ciphertext, metadata...)
	if err != nil {
		encryptor.logger.Printf("decryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("decryption success")

	return plaintext, nil
}

func (encryptor *LogEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
