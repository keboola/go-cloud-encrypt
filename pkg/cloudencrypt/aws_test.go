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

	err := os.Setenv("AWS_ACCESS_KEY_ID", os.Getenv("TEST_AWS_ACCESS_KEY_ID"))
	require.NoError(t, err)

	err = os.Setenv("AWS_SECRET_ACCESS_KEY", os.Getenv("TEST_AWS_SECRET_ACCESS_KEY"))
	require.NoError(t, err)

	err = os.Setenv("AWS_ROLE_ID", os.Getenv("TEST_AWS_ROLE_ID"))
	require.NoError(t, err)

	region := os.Getenv("TEST_AWS_REGION")
	if region == "" {
		require.Fail(t, "TEST_AWS_REGION is empty")
	}

	keyID := os.Getenv("TEST_AWS_KMS_KEY_ID")
	if keyID == "" {
		require.Fail(t, "TEST_AWS_KMS_KEY_ID is empty")
	}

	encryptor, err := NewAWSEncryptor(ctx, region, keyID)
	require.NoError(t, err)

	meta := MetadataKV{
		Key:   "metakey",
		Value: "metavalue",
	}

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext)
	assert.ErrorContains(t, err, "aws decryption failed: operation error KMS: Decrypt")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
