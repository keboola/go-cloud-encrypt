package cloudencrypt_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestAzureEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	vaultURL := os.Getenv("AZURE_KEY_VAULT_URL")
	if vaultURL == "" {
		require.Fail(t, "AZURE_KEY_VAULT_URL is empty")
	}

	keyName := os.Getenv("AZURE_KEY_NAME")
	if keyName == "" {
		require.Fail(t, "AZURE_KEY_NAME is empty")
	}

	azureEncryptor, err := cloudencrypt.NewAzureEncryptor(ctx, vaultURL, keyName)
	require.NoError(t, err)

	encryptor, err := cloudencrypt.NewDualEncryptor(ctx, azureEncryptor)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "decryption failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	require.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
