package kbcenvelope

import (
	"bytes"
	"compress/zlib"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compressForTest(t *testing.T, plain string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write([]byte(plain))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	return buf.Bytes()
}

// A cipher text arrives inside a user's configuration, so its compressed bytes are
// attacker-controlled. zlib expands a few kilobytes into hundreds of megabytes, and the
// calling process is typically shared across many tenants, so the inflate must be bounded.
func TestDecodeAWSCipherDataRejectsDecompressionBomb(t *testing.T) {
	t.Parallel()

	const inflated = 64 << 20 // 64 MiB of zeros compresses to well under 100 KiB

	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	require.NoError(t, err)

	chunk := make([]byte, 1<<20)
	for range inflated >> 20 {
		_, writeErr := zw.Write(chunk)
		require.NoError(t, writeErr)
	}

	require.NoError(t, zw.Close())

	require.Less(t, buf.Len(), 1<<20, "the bomb must be small enough to sit in a config")

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err = DecodeAWSEnvelope(buf.Bytes())

	runtime.ReadMemStats(&after)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the")

	allocated := after.TotalAlloc - before.TotalAlloc
	assert.Less(t, allocated, uint64(16<<20),
		"decoding must not allocate anywhere near the %d bytes the bomb inflates to", inflated)
}

func TestDecodeAWSCipherDataAcceptsNormalSize(t *testing.T) {
	t.Parallel()

	payload, key := "PAYLOAD", "KEYBLOB"
	serialized := `a:2:{i:0;s:7:"` + payload + `";i:1;s:7:"` + key + `";}`

	data, err := DecodeAWSEnvelope(compressForTest(t, serialized))

	require.NoError(t, err)
	assert.Equal(t, payload, string(data.EncryptedPayload))
	assert.Equal(t, key, string(data.EncryptedKey))
}

func TestDecodeGCPCipherDataIndexOrderIsSwapped(t *testing.T) {
	t.Parallel()

	key, payload := "KEYBLOB", "PAYLOAD"
	serialized := `a:2:{i:0;s:7:"` + key + `";i:1;s:7:"` + payload + `";}`

	data, err := DecodeGCPEnvelope(compressForTest(t, serialized))

	require.NoError(t, err)
	assert.Equal(t, payload, string(data.EncryptedPayload))
	assert.Equal(t, key, string(data.EncryptedKey))
}

func TestDecodeAzureCipherData(t *testing.T) {
	t.Parallel()

	payload, name, version := "PAYLOAD", "my-secret", "v1"
	serialized := `a:3:{i:2;s:7:"` + payload + `";i:3;s:9:"` + name + `";i:4;s:2:"` + version + `";}`

	data, err := DecodeAzureEnvelope(compressForTest(t, serialized))

	require.NoError(t, err)
	assert.Equal(t, payload, string(data.EncryptedPayload))
	assert.Equal(t, name, data.SecretName)
	assert.Equal(t, version, data.SecretVersion)
}

// The serialized string length is attacker-controlled. Comparing it as pos+strLen overflows for
// a length near maxint, wraps negative, slips past the bounds check and panics on the slice —
// reachable from any configuration value.
func TestDecodeAWSCipherDataRejectsOverflowingStringLength(t *testing.T) {
	t.Parallel()

	for _, declared := range []string{
		"9223372036854775807",  // maxint64
		"99999999999999999999", // beyond int64 entirely
	} {
		t.Run(declared, func(t *testing.T) {
			t.Parallel()

			serialized := `a:1:{i:0;s:` + declared + `:"AB";}`

			require.NotPanics(t, func() {
				_, err := DecodeAWSEnvelope(compressForTest(t, serialized))
				assert.Error(t, err)
			})
		})
	}
}

// Fuzz the decode path on hostile input: a config value is attacker-controlled all the way down
// to the PHP-serialized bytes.
func FuzzDecodeAWSCipherData(f *testing.F) {
	seeds := []string{
		`a:2:{i:0;s:7:"PAYLOAD";i:1;s:7:"KEYBLOB";}`,
		`a:1:{i:0;s:9223372036854775807:"AB";}`,
		`a:0:{}`,
		`a:99:{i:0;s:1:"A";}`,
		`a:1:{i:0;s:0:"";}`,
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte(body))
		_ = zw.Close()

		// Must never panic, whatever the bytes say.
		_, _ = DecodeAWSEnvelope(buf.Bytes())
	})
}
