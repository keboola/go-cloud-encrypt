package cloudencrypt

import (
	"bytes"
	"context"
	"log"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/keboola/go-utils/pkg/wildcards"
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

	config := &ristretto.Config[[]byte, []byte]{
		NumCounters: 1e4,
		MaxCost:     1 << 20,
		BufferItems: 64,
	}

	cache, err := ristretto.NewCache(config)
	assert.NoError(t, err)

	encryptor, err := NewCacheEncryptor(
		ctx,
		logEncryptor,
		time.Hour,
		cache,
	)
	assert.NoError(t, err)

	meta := MetadataKV{
		Key:   "metakey",
		Value: "metavalue",
	}

	ciphertext, err := encryptor.Encrypt(ctx, []byte("Lorem ipsum"), meta)
	assert.NoError(t, err)

	// Wait for cached item to be available for get operations
	cache.Wait()

	_, err = encryptor.Decrypt(ctx, ciphertext)
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	plaintext, err := encryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, []byte("Lorem ipsum"), plaintext)

	wildcards.Assert(t, `encryption success
decryption error:%s cipher: message authentication failed
`, buffer.String())
}
