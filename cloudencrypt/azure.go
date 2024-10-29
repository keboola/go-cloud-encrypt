package cloudencrypt

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/pkg/errors"
)

const (
	mapKeyMetadata = "metadata"
	mapKeySecret   = "secret"
)

// AzureEncryptor Implements Encryptor by saving the value as a secret in Azure's Key Vault.
type AzureEncryptor struct {
	client       *keyvault.BaseClient
	vaultBaseURL string
	secretPrefix string
}

func NewAzureEncryptor(ctx context.Context, vaultBaseURL, secretPrefix string) (*AzureEncryptor, error) {
	client := keyvault.New()

	return &AzureEncryptor{
		client:       &client,
		vaultBaseURL: vaultBaseURL,
		secretPrefix: secretPrefix,
	}, nil
}

func (encryptor *AzureEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	additionalData, err := encode(buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	secretValueData := make(map[string]string)
	secretValueData[mapKeyMetadata] = string(additionalData)
	secretValueData[mapKeySecret] = string(value)
	secretValue, err := encode(secretValueData)
	if err != nil {
		return nil, err
	}
	secretValueString := string(secretValue)

	random, err := rand.Int(rand.Reader, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "can't generate random int: %s", err.Error())
	}
	secretName := fmt.Sprintf("%s-%d-%d", encryptor.secretPrefix, time.Now().Unix(), random)

	secret, err := encryptor.client.SetSecret(
		ctx,
		encryptor.vaultBaseURL,
		secretName,
		keyvault.SecretSetParameters{
			Value: &secretValueString,
		},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "azure set secret failed: %s", err.Error())
	}

	return []byte(*secret.ID), nil
}

func (encryptor *AzureEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	parts := strings.Split(string(encryptedValue), "/")
	if len(parts) != 4 {
		return nil, errors.New("unable to parse secret id")
	}

	secret, err := encryptor.client.GetSecret(ctx, encryptor.vaultBaseURL, parts[2], parts[3])
	if err != nil {
		return nil, errors.Wrapf(err, "azure get secret failed: %s", err.Error())
	}

	secretData, err := decode([]byte(*secret.Value))
	if err != nil {
		return nil, err
	}

	metadataMap, err := decode([]byte(secretData[mapKeyMetadata]))
	if err != nil {
		return nil, err
	}

	err = verifyMetadata(metadataMap, buildMetadataMap(metadata...))
	if err != nil {
		return nil, err
	}

	return []byte(secretData[mapKeySecret]), nil
}

func (encryptor *AzureEncryptor) Close() error {
	return nil
}

func verifyMetadata(expected, actual map[string]string) error {
	if len(expected) != len(actual) {
		return errors.New("decryption failed")
	}

	for k, v := range expected {
		av, ok := actual[k]
		if !ok || av != v {
			return errors.New("decryption failed")
		}
	}

	return nil
}
