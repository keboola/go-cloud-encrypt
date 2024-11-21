package cloudencrypt

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/pkg/errors"
)

// AWSEncryptor Implements Encryptor using AWS Key Management Service.
type AWSEncryptor struct {
	client *kms.Client
	keyID  string
}

func NewAWSEncryptor(ctx context.Context, region, keyID string) (*AWSEncryptor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, errors.Wrapf(err, "can't create aws config: %s", err.Error())
	}

	client := kms.NewFromConfig(cfg)

	return &AWSEncryptor{
		client: client,
		keyID:  keyID,
	}, nil
}

func (encryptor *AWSEncryptor) Encrypt(ctx context.Context, plaintext []byte, metadata Metadata) ([]byte, error) {
	encryptInput := &kms.EncryptInput{
		KeyId:             &encryptor.keyID,
		Plaintext:         plaintext,
		EncryptionContext: metadata,
	}

	encryptOutput, err := encryptor.client.Encrypt(ctx, encryptInput)
	if err != nil {
		return nil, errors.Wrapf(err, "aws encryption failed: %s", err.Error())
	}

	return encryptOutput.CiphertextBlob, nil
}

func (encryptor *AWSEncryptor) Decrypt(ctx context.Context, ciphertext []byte, metadata Metadata) ([]byte, error) {
	decryptInput := &kms.DecryptInput{
		KeyId:             &encryptor.keyID,
		CiphertextBlob:    ciphertext,
		EncryptionContext: metadata,
	}

	decryptOutput, err := encryptor.client.Decrypt(ctx, decryptInput)
	if err != nil {
		return nil, errors.Wrapf(err, "aws decryption failed: %s", err.Error())
	}

	return decryptOutput.Plaintext, nil
}

func (encryptor *AWSEncryptor) Close() error {
	return nil
}
