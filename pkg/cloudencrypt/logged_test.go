package cloudencrypt_test

import (
	"bytes"
	"context"
	"log"
	"testing"

	"github.com/keboola/go-utils/pkg/wildcards"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func TestLoggedEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := random.SecretKey()
	require.NoError(t, err)

	aesEncryptor, err := cloudencrypt.NewAESEncryptor(secretKey)
	require.NoError(t, err)

	var buffer bytes.Buffer
	logger := log.New(&buffer, "", 0)

	encryptor, err := cloudencrypt.NewLoggedEncryptor(aesEncryptor, logger)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	require.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	require.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)

	wildcards.Assert(t, `encryption success
decryption error:%s cipher: message authentication failed
decryption success
`, buffer.String())
}
