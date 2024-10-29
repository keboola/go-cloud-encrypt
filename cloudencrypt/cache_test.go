package cloudencrypt

import (
	"bytes"
	"context"
	"log"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/stretchr/testify/assert"
)

func Test_CacheEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := generateSecretKey()
	assert.NoError(t, err)

	nativeEncryptor, err := NewNativeEncryptor(secretKey)
	assert.NoError(t, err)

	var buffer bytes.Buffer
	logger := log.New(&buffer, "", 0)

	logEncryptor, err := NewLogEncryptor(ctx, nativeEncryptor, logger)
	assert.NoError(t, err)

	encryptor, err := NewCacheEncryptor(
		ctx,
		logEncryptor,
		time.Hour,
		&ristretto.Config[[]byte, []byte]{
			NumCounters: 1e4,
			MaxCost:     1 << 20,
			BufferItems: 64,
		},
	)
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

	assert.Equal(t, `encryption success
decryption error: cipher: message authentication failed
`, buffer.String())
}
