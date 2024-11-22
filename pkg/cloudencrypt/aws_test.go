package cloudencrypt_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestAWSEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	region := os.Getenv("AWS_REGION")
	if region == "" {
		require.Fail(t, "AWS_REGION is empty")
	}

	keyID := os.Getenv("AWS_KMS_KEY_ID")
	if keyID == "" {
		require.Fail(t, "AWS_KMS_KEY_ID is empty")
	}

	encryptor, err := cloudencrypt.NewAWSEncryptor(ctx, region, keyID)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "aws decryption failed: operation error KMS: Decrypt")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
