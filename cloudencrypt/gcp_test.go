package cloudencrypt

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GCPEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", os.Getenv("TEST_GOOGLE_APPLICATION_CREDENTIALS"))
	require.NoError(t, err)

	keyID := os.Getenv("TEST_GCP_KMS_KEY_ID")
	if keyID == "" {
		require.Fail(t, "TEST_GCP_KMS_KEY_ID is empty")
	}

	encryptor, err := NewGCPEncryptor(ctx, keyID)
	require.NoError(t, err)

	meta := MetadataKV{
		Key:   "metakey",
		Value: "metavalue",
	}

	encrypted, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, encrypted)
	assert.ErrorContains(t, err, "gcp decryption failed: rpc error: code = InvalidArgument")

	decrypted, err := encryptor.Decrypt(ctx, encrypted, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), decrypted)
}
