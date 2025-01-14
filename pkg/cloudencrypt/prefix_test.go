package cloudencrypt_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestPrefixEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := random.SecretKey()
	require.NoError(t, err)

	nativeEncryptor, err := cloudencrypt.NewNativeEncryptor(secretKey)
	require.NoError(t, err)

	encryptor, err := cloudencrypt.NewPrefixEncryptor(ctx, nativeEncryptor, []byte("Prefix::"))
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(ciphertext[0:8], []byte("Prefix::")))

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	require.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
