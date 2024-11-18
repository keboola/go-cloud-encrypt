package cloudencrypt

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	encryptor, err := NewAWSEncryptor(ctx, region, keyID)
	require.NoError(t, err)

	meta := Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, Metadata{})
	assert.ErrorContains(t, err, "aws decryption failed: operation error KMS: Decrypt")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
