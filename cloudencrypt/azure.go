package cloudencrypt

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/pkg/errors"
)

const (
	mapKeyMetadata = "metadata"
	mapKeySecret   = "secret"
)

// AzureEncryptor Implements Encryptor by saving the value as a secret in Azure's Key Vault.
type AzureEncryptor struct {
	client       *azsecrets.Client
	vaultBaseURL string
	secretPrefix string
}

func NewAzureEncryptor(ctx context.Context, vaultBaseURL, secretPrefix string) (*AzureEncryptor, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(vaultBaseURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return &AzureEncryptor{
		client:       client,
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

	random, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, errors.Wrapf(err, "can't generate random int: %s", err.Error())
	}
	secretName := fmt.Sprintf("%s-%d-%d", encryptor.secretPrefix, time.Now().Unix(), random)

	_, err = encryptor.client.SetSecret(
		ctx,
		secretName,
		azsecrets.SetSecretParameters{
			Value: &secretValueString,
		},
		nil,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "azure set secret failed: %s", err.Error())
	}

	return []byte(secretName), nil
}

func (encryptor *AzureEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	//parts := strings.Split(string(encryptedValue), "/")
	//if len(parts) != 4 {
	//	fmt.Println(string(encryptedValue))
	//	return nil, errors.New("unable to parse secret id")
	//}

	secret, err := encryptor.client.GetSecret(ctx, string(encryptedValue), "", nil)
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
