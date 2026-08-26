package kbcenvelope

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Real Azure cipher text from PHP fixtures (id=113, simple_string), prefix and base64 layer
// stripped exactly as cloudencrypt.PrefixEncryptor + Base64Encryptor would before handing the
// remaining bytes to AzureEncryptor.Decrypt.
var azureTestCiphertext = mustBase64Decode(strings.TrimPrefix(
	"KBC::SecureKV::eJxLtDK2qs60MrIutjI0MLZSuveViUE3duHCn2Ki1RfvzHXceu/frjvzEuomWMcLayxW+3nM9vjJaxPn7FzfsmOS95052zPWvKn+lxu1+tCypZ921R7lnFG6e2PVbffvWssnss/7vi6Ha3q7XQoLO49FNMfrYzed/Bf2iqx+n66mZJ1pZQy009jMSsk4KcnA2NDQRDcpNclC1yQpxVzXIskcyDVMMjI0NklOtrBIBKk3Aak3slIysjQ2MTKxMDc3N0sxMTE1SDRNTjY3tDQ0STG3MDM2SFOyrgUA2WdS9w==",
	"KBC::SecureKV::",
))

func mustBase64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}

type mockAKVClient struct {
	mock.Mock
}

func (m *mockAKVClient) GetSecret(ctx context.Context, secretName, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	args := m.Called(ctx, secretName, version, options)

	return args.Get(0).(azsecrets.GetSecretResponse), args.Error(1)
}

// TestAzureEncryptor_DecryptIgnoresEmbeddedVersion verifies that decryption always fetches the
// latest secret version, even though the cipher text embeds a specific one.
func TestAzureEncryptor_DecryptIgnoresEmbeddedVersion(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	mockClient := new(mockAKVClient)
	mockClient.On("GetSecret", ctx, mock.Anything, "", (*azsecrets.GetSecretOptions)(nil)).
		Return(azsecrets.GetSecretResponse{}, errors.New("test error"))

	enc := NewAzureEncryptor(mockClient)

	_, _ = enc.Decrypt(ctx, azureTestCiphertext, nil)

	mockClient.AssertCalled(t, "GetSecret", ctx, mock.Anything, "", (*azsecrets.GetSecretOptions)(nil))
}

func TestAzureEncryptor_DecryptErrorHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupMock     func(*mockAKVClient)
		expectedError string
		wantBackend   bool // true => failure of the remote GetSecret call
	}{
		{
			name: "GetSecret fails is a backend error",
			setupMock: func(m *mockAKVClient) {
				m.On("GetSecret", mock.Anything, mock.Anything, "", mock.Anything).
					Return(azsecrets.GetSecretResponse{}, errors.New("network error"))
			},
			expectedError: "failed to get secret from Key Vault",
			wantBackend:   true,
		},
		{
			name: "secret value is nil is a local (data) error",
			setupMock: func(m *mockAKVClient) {
				m.On("GetSecret", mock.Anything, mock.Anything, "", mock.Anything).
					Return(azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: nil}}, nil)
			},
			expectedError: "secret value is nil",
			wantBackend:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			mockClient := new(mockAKVClient)
			tt.setupMock(mockClient)

			enc := NewAzureEncryptor(mockClient)

			_, err := enc.Decrypt(ctx, azureTestCiphertext, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)

			var be *BackendError
			assert.Equal(t, tt.wantBackend, errors.As(err, &be),
				"BackendError classification mismatch for %q", tt.name)
		})
	}
}

func TestVerifyMetadataSubset(t *testing.T) {
	t.Parallel()

	stored := map[string]string{"stackId": "s1", "componentId": "c1", "extra": "allowed"}

	assert.NoError(t, verifyMetadataSubset(stored, nil))
	assert.NoError(t, verifyMetadataSubset(stored, map[string]string{"stackId": "s1"}))
	assert.NoError(t, verifyMetadataSubset(stored, map[string]string{"stackId": "s1", "componentId": "c1"}))
	assert.Error(t, verifyMetadataSubset(stored, map[string]string{"stackId": "wrong"}))
	assert.Error(t, verifyMetadataSubset(stored, map[string]string{"missing": "x"}))
}
