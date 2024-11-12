package cloudencrypt

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AzureEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	err := os.Setenv("AZURE_TENANT_ID", os.Getenv("TEST_AZURE_TENANT_ID"))
	require.NoError(t, err)

	err = os.Setenv("AZURE_CLIENT_ID", os.Getenv("TEST_AZURE_CLIENT_ID"))
	require.NoError(t, err)

	err = os.Setenv("AZURE_CLIENT_SECRET", os.Getenv("TEST_AZURE_CLIENT_SECRET"))
	require.NoError(t, err)

	vaultURL := os.Getenv("TEST_AZURE_KEY_VAULT_URL")
	if vaultURL == "" {
		require.Fail(t, "TEST_AZURE_KEY_VAULT_URL is empty")
	}

	keyName := os.Getenv("TEST_AZURE_KEY_NAME")
	if keyName == "" {
		require.Fail(t, "TEST_AZURE_KEY_NAME is empty")
	}

	azureEncryptor, err := NewAzureEncryptor(ctx, vaultURL, keyName)
	require.NoError(t, err)

	encryptor, err := NewDualEncryptor(ctx, azureEncryptor)
	require.NoError(t, err)

	meta := MetadataKV{
		Key:   "metakey",
		Value: "metavalue",
	}

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext)
	assert.ErrorContains(t, err, "decryption failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
