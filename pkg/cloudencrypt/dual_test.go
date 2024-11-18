package cloudencrypt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDualEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := generateSecretKey()
	assert.NoError(t, err)

	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	assert.NoError(t, err)

	encryptor, err := NewDualEncryptor(ctx, nativeEncryptor)
	assert.NoError(t, err)

	meta := Metadata{}
	meta["metakey"] = "metavalue"

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	assert.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, ciphertext, Metadata{})
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)
}
