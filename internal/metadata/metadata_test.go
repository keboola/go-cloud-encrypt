package metadata_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keboola/go-cloud-encrypt/internal/metadata"
	"github.com/keboola/go-cloud-encrypt/internal/random"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	secretKey, err := random.SecretKey()
	assert.NoError(t, err)

	data1 := make(map[string]string)
	data1["test1"] = string(secretKey)
	data1["test2"] = string(secretKey)

	data2 := make(map[string]string)
	data2["test2"] = string(secretKey)
	data2["test1"] = string(secretKey)

	encoded1, err := metadata.Encode(data1)
	assert.NoError(t, err)
	assert.NotNil(t, encoded1)

	encoded2, err := metadata.Encode(data2)
	assert.NoError(t, err)
	assert.NotNil(t, encoded2)

	assert.Equal(t, encoded1, encoded2)
}
