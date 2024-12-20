package encode_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keboola/go-cloud-encrypt/internal/encode"
	"github.com/keboola/go-cloud-encrypt/internal/random"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	secretKey, err := random.SecretKey()
	assert.NoError(t, err)

	data := make(map[string][]byte)
	data["test"] = secretKey
	data["a"] = secretKey
	data["test2"] = secretKey

	encoded, err := encode.Encode(data)
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	fmt.Println(string(encoded))

	decoded, err := encode.Decode[map[string][]byte](encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	for k, v := range decoded {
		fmt.Println(k, string(v))
	}

	assert.Equal(t, data, decoded)
}
