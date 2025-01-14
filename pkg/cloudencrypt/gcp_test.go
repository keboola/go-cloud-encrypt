package cloudencrypt_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestGCPEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	keyID := os.Getenv("GCP_KMS_KEY_ID")
	if keyID == "" {
		require.Fail(t, "GCP_KMS_KEY_ID is empty")
	}

	encryptor, err := cloudencrypt.NewGCPEncryptor(ctx, keyID)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "gcp decryption failed: rpc error: code = InvalidArgument")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	require.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
