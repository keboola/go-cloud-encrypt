package kbcenvelope

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeAWSEnvelopeForTest builds the base64(zlib(phpserialize([0=>payload, 1=>key]))) text a
// caller strips the "KBC::...::" prefix off before base64-decoding — i.e. everything after it.
func encodeAWSEnvelopeForTest(t *testing.T, payload, key string) string {
	t.Helper()

	serialized := fmt.Sprintf("a:2:{i:0;s:%d:\"%s\";i:1;s:%d:\"%s\";}", len(payload), payload, len(key), key)

	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	_, err := zw.Write([]byte(serialized))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

type stubKMSClient struct {
	calls       int
	lastContext map[string]string
}

func (s *stubKMSClient) Decrypt(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	s.calls++
	s.lastContext = params.EncryptionContext

	return nil, errors.New("stub KMS: refusing to decrypt")
}

func TestMetadataForScope(t *testing.T) {
	t.Parallel()

	in := ScopeInputs{ComponentID: "c", ProjectID: "p", ConfigurationID: "cfg", BranchType: "default"}

	assert.Nil(t, MetadataForScope(ScopeGeneric, "stack", in))
	assert.Equal(t, map[string]string{"stackId": "stack", "componentId": "c"}, MetadataForScope(ScopeComponent, "stack", in))
	assert.Equal(t, map[string]string{"stackId": "stack", "componentId": "c", "projectId": "p"}, MetadataForScope(ScopeProject, "stack", in))
	assert.Equal(t, map[string]string{"stackId": "stack", "projectId": "p"}, MetadataForScope(ScopeProjectWide, "stack", in))
	assert.Equal(t, map[string]string{
		"stackId": "stack", "componentId": "c", "projectId": "p", "configurationId": "cfg", "branchType": "default",
	}, MetadataForScope(ScopeBranchTypeConfiguration, "stack", in))
}

func TestLookupPrefix(t *testing.T) {
	t.Parallel()

	prefix, info, ok := LookupPrefix(PrefixComponentKMS + "eJxL...")
	require.True(t, ok)
	assert.Equal(t, PrefixComponentKMS, prefix)
	assert.Equal(t, PrefixInfo{ProviderAWS, ScopeComponent}, info)

	_, _, ok = LookupPrefix("not-a-cipher-text")
	assert.False(t, ok)

	_, _, ok = LookupPrefix("KBC::NotARealPrefix::eJxL...")
	assert.False(t, ok, "well-formed KBC:: shape but not in PrefixTable")
}

func TestDecryptCipherText_LegacyPrefixIsRejected(t *testing.T) {
	t.Parallel()

	for _, legacy := range LegacyPrefixes {
		_, err := DecryptCipherText(t.Context(), legacy+"anything", Clients{}, "stack", ScopeInputs{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrLegacyCipherFormat)
	}
}

func TestDecryptCipherText_UnknownPrefixIsRejected(t *testing.T) {
	t.Parallel()

	_, err := DecryptCipherText(t.Context(), "KBC::NotARealPrefix::abc", Clients{}, "stack", ScopeInputs{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownPrefix)
}

func TestDecryptCipherText_ForeignCloudIsRejectedWithoutDereferencingNilClient(t *testing.T) {
	t.Parallel()

	// Only GCP configured; an AWS-prefixed cipher must be rejected, not panic on a nil AWS client.
	clients := Clients{GCP: nil} //nolint:exhaustruct // deliberately leaving AWS/Azure unset

	var (
		err      error
		panicked any
	)

	func() {
		defer func() { panicked = recover() }()
		_, err = DecryptCipherText(t.Context(), PrefixComponentKMS+"abc", clients, "stack", ScopeInputs{})
	}()

	require.Nil(t, panicked)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestDecryptCipherText_BuildsExactScopeMetadataAndReachesTheEngine(t *testing.T) {
	t.Parallel()

	payload, key := "PAYLOAD-NOT-A-REAL-SECRET", "ENCRYPTED-KEY-BLOB"
	cipherText := PrefixComponentKMS + encodeAWSEnvelopeForTest(t, payload, key)

	stub := &stubKMSClient{}
	clients := Clients{AWS: stub, AWSKeyID: "test-key"} //nolint:exhaustruct

	_, err := DecryptCipherText(t.Context(), cipherText, clients, "my-stack", ScopeInputs{ComponentID: "my-component", ProjectID: "ignored-for-component-scope"})

	require.Error(t, err) // stub KMS always fails; we're asserting on what it was called with
	assert.Positive(t, stub.calls)
	assert.Equal(t, map[string]string{"stackId": "my-stack", "componentId": "my-component"}, stub.lastContext,
		"component-scoped ciphers bind only stackId+componentId, ignoring the caller's projectId")
}
