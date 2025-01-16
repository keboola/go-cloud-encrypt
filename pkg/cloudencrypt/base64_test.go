package cloudencrypt_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestBase64Encryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := random.SecretKey()
	require.NoError(t, err)

	aesEncryptor, err := cloudencrypt.NewAESEncryptor(secretKey)
	require.NoError(t, err)

	encryptor, err := cloudencrypt.NewBase64Encryptor(aesEncryptor)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte(" "), meta)
	require.NoError(t, err)

	_, err = base64.StdEncoding.DecodeString(string(ciphertext))
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	require.NoError(t, err)

	assert.Equal(t, []byte(" "), plaintext)
}
