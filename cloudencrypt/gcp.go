package cloudencrypt

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/pkg/errors"
)

// GCPEncryptor Implements Encryptor using Google Cloud's Key Management Service.
type GCPEncryptor struct {
	client *kms.KeyManagementClient
	keyID  string
}

func NewGCPEncryptor(ctx context.Context, keyID string) (*GCPEncryptor, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "can't create gpc kms client: %s", err.Error())
	}

	return &GCPEncryptor{
		client: client,
		keyID:  keyID,
	}, nil
}

func (encryptor *GCPEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	additionalData, err := encode(buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	request := &kmspb.EncryptRequest{
		Name:                        encryptor.keyID,
		Plaintext:                   value,
		AdditionalAuthenticatedData: additionalData,
	}

	response, err := encryptor.client.Encrypt(ctx, request)
	if err != nil {
		return nil, errors.Wrapf(err, "gcp encryption failed: %s", err.Error())
	}

	return response.GetCiphertext(), nil
}

func (encryptor *GCPEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	additionalData, err := encode(buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	request := &kmspb.DecryptRequest{
		Name:                        encryptor.keyID,
		Ciphertext:                  encryptedValue,
		AdditionalAuthenticatedData: additionalData,
	}

	response, err := encryptor.client.Decrypt(ctx, request)
	if err != nil {
		return nil, errors.Wrapf(err, "gcp decryption failed: %s", err.Error())
	}

	return response.GetPlaintext(), nil
}

func (encryptor *GCPEncryptor) Close() error {
	err := encryptor.client.Close()
	if err != nil {
		return errors.Wrapf(err, "can't close gcp client: %s", err.Error())
	}

	return nil
}
