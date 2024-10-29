package cloudencrypt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NativeEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := generateSecretKey()
	assert.NoError(t, err)

	encryptor, err := NewNativeEncryptor(secretKey)
	assert.NoError(t, err)

	meta := MetadataKV{
		Key:   "metakey",
		Value: "metavalue",
	}

	encrypted, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	assert.NoError(t, err)

	_, err = encryptor.Decrypt(ctx, encrypted)
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	decrypted, err := encryptor.Decrypt(ctx, encrypted, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), decrypted)
}
