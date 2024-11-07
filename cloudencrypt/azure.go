package cloudencrypt

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// AzureEncryptor Implements Encryptor by saving the value as a secret in Azure's Key Vault.
type AzureEncryptor struct {
	client  *azkeys.Client
	keyName string
}

func NewAzureEncryptor(ctx context.Context, vaultBaseURL, keyName string) (*AzureEncryptor, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := azkeys.NewClient(vaultBaseURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return &AzureEncryptor{
		client:  client,
		keyName: keyName,
	}, nil
}

func (encryptor *AzureEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	result, err := encryptor.client.Encrypt(
		ctx,
		encryptor.keyName,
		"",
		azkeys.KeyOperationParameters{
			Algorithm: &algorithm,
			Value:     value,
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	return result.Result, nil
}

func (encryptor *AzureEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	result, err := encryptor.client.Decrypt(
		ctx,
		encryptor.keyName,
		"",
		azkeys.KeyOperationParameters{
			Algorithm: &algorithm,
			Value:     encryptedValue,
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	return result.Result, nil
}

func (encryptor *AzureEncryptor) Close() error {
	return nil
}
