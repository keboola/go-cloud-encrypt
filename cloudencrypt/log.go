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

func (encryptor *LogEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, value, metadata...)
	if err != nil {
		encryptor.logger.Printf("encryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("encryption success")

	return encryptedValue, nil
}

func (encryptor *LogEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	decrypted, err := encryptor.encryptor.Decrypt(ctx, encryptedValue, metadata...)
	if err != nil {
		encryptor.logger.Printf("decryption error: %s", err.Error())
		return nil, err
	}

	encryptor.logger.Println("decryption success")

	return decrypted, nil
}

func (encryptor *LogEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
