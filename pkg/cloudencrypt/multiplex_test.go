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

func TestMultiplexEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	encryptorFactory := func(ctx context.Context, prefix []byte) (*cloudencrypt.PrefixEncryptor, error) {
		secretKey, err := random.SecretKey()
		require.NoError(t, err)

		aesEncryptor, err := cloudencrypt.NewAESEncryptor(secretKey)
		require.NoError(t, err)

		return cloudencrypt.NewPrefixEncryptor(ctx, aesEncryptor, prefix)
	}

	newEncryptor, err := encryptorFactory(ctx, []byte("New::"))
	require.NoError(t, err)

	oldEncryptor, err := encryptorFactory(ctx, []byte("Old::"))
	require.NoError(t, err)

	decryptors := []*cloudencrypt.PrefixEncryptor{oldEncryptor}

	encryptor, err := cloudencrypt.NewMultiplexEncryptor(ctx, newEncryptor, decryptors)
	require.NoError(t, err)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	// Standard flow using newEncryptor
	{
		ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
		require.NoError(t, err)

		assert.True(t, bytes.Equal(ciphertext[0:5], []byte("New::")))

		_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
		assert.ErrorContains(t, err, "cipher: message authentication failed")

		plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
		require.NoError(t, err)

		assert.Equal(t, []byte("Lorem ipsum"), plaintext)
	}

	// Decrypt a value using oldEncryptor
	{
		ciphertext, err := oldEncryptor.Encrypt(ctx, []byte("dolor sit amet"), meta)
		require.NoError(t, err)

		assert.True(t, bytes.Equal(ciphertext[0:5], []byte("Old::")))

		_, err = encryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
		assert.ErrorContains(t, err, "cipher: message authentication failed")

		plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
		require.NoError(t, err)

		assert.Equal(t, []byte("dolor sit amet"), plaintext)
	}
}
