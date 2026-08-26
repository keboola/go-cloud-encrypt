//go:build cgo

package kbcenvelope

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// TestGoogleAADMatchesPHP pins the exact bytes PHP's gzcompress() produces for an empty
// encryption context. This is the byte-for-byte compatibility the CGO/libz build (zlib_cgo.go)
// exists for: Go's standard compress/zlib writer adds sync-flush markers PHP's gzcompress()
// doesn't, which would otherwise make Google KMS reject the AAD on every real decrypt.
func TestGoogleAADMatchesPHP(t *testing.T) {
	t.Parallel()

	const phpExpectedBase64 = "eJxLtDKwqq4FAAZPAf4="
	const phpExpectedHex = "789c4bb432b0aaae0500064f01fe"

	aad, err := googleAAD(nil)
	require.NoError(t, err)

	assert.Equal(t, phpExpectedBase64, string(aad))

	decoded, err := base64.StdEncoding.DecodeString(string(aad))
	require.NoError(t, err)
	assert.Equal(t, phpExpectedHex, hex.EncodeToString(decoded))
}

func TestGoogleAADIsValidZlibOfSortedPHPArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		context cloudencrypt.Metadata
	}{
		{"nil context", nil},
		{"empty context", cloudencrypt.Metadata{}},
		{"single key", cloudencrypt.Metadata{"stackId": "my-stack"}},
		{"multiple keys", cloudencrypt.Metadata{"projectId": "123", "componentId": "my-component", "stackId": "my-stack"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aad, err := googleAAD(tt.context)
			require.NoError(t, err)
			require.NotEmpty(t, aad)

			decoded, err := base64.StdEncoding.DecodeString(string(aad))
			require.NoError(t, err, "AAD is not valid base64")

			zlibReader, err := zlib.NewReader(bytes.NewReader(decoded))
			require.NoError(t, err, "AAD is not valid zlib")
			defer zlibReader.Close()

			serialized, err := io.ReadAll(zlibReader)
			require.NoError(t, err)
			assert.True(t, bytes.HasPrefix(serialized, []byte("a:")), "serialized data doesn't start with PHP array marker")
		})
	}
}

func TestGoogleAADKeysAreSorted(t *testing.T) {
	t.Parallel()

	context := cloudencrypt.Metadata{
		"z_last":   "value1",
		"m_middle": "value2",
		"a_first":  "value3",
	}

	aad, err := googleAAD(context)
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(string(aad))
	require.NoError(t, err)

	zlibReader, err := zlib.NewReader(bytes.NewReader(decoded))
	require.NoError(t, err)

	serialized, err := io.ReadAll(zlibReader)
	require.NoError(t, err)

	posA := bytes.Index(serialized, []byte("a_first"))
	posM := bytes.Index(serialized, []byte("m_middle"))
	posZ := bytes.Index(serialized, []byte("z_last"))

	require.NotEqual(t, -1, posA)
	require.NotEqual(t, -1, posM)
	require.NotEqual(t, -1, posZ)
	assert.Less(t, posA, posM, "a_first should come before m_middle")
	assert.Less(t, posM, posZ, "m_middle should come before z_last")
}
