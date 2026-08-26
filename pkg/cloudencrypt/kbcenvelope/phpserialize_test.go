package kbcenvelope

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

type deserializeValidCase struct {
	name     string
	input    string
	expected map[any]any
}

func validDeserializeCases() []deserializeValidCase {
	return []deserializeValidCase{
		{
			name:  "simple_two_element_array",
			input: `a:2:{i:0;s:5:"hello";i:1;s:5:"world";}`,
			expected: map[any]any{
				int64(0): "hello",
				int64(1): "world",
			},
		},
		{
			name:  "empty_strings",
			input: `a:2:{i:0;s:0:"";i:1;s:0:"";}`,
			expected: map[any]any{
				int64(0): "",
				int64(1): "",
			},
		},
		{
			name:  "binary_data_with_nulls",
			input: "a:1:{i:0;s:10:\"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\";}",
			expected: map[any]any{
				int64(0): "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
			},
		},
		{
			name:  "binary_data_with_quotes",
			input: `a:1:{i:0;s:10:"abc"def"gh";}`,
			expected: map[any]any{
				int64(0): `abc"def"gh`,
			},
		},
		{
			name:  "defuse_encryption_header",
			input: "a:2:{i:0;s:4:\"\xDE\xF5\x02\x00\";i:1;s:3:\"key\";}",
			expected: map[any]any{
				int64(0): "\xDE\xF5\x02\x00",
				int64(1): "key",
			},
		},
		{
			name:  "large_index_numbers",
			input: `a:2:{i:99;s:5:"hello";i:100;s:5:"world";}`,
			expected: map[any]any{
				int64(99):  "hello",
				int64(100): "world",
			},
		},
		{
			name:  "long_string",
			input: `a:1:{i:0;s:1000:"` + strings.Repeat("A", 1000) + `";}`,
			expected: map[any]any{
				int64(0): strings.Repeat("A", 1000),
			},
		},
	}
}

func TestManualPHPDeserializeArray_ValidFormats(t *testing.T) {
	t.Parallel()

	for _, tc := range validDeserializeCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := manualPHPDeserializeArray([]byte(tc.input))
			require.NoError(t, err)
			assert.Len(t, result, len(tc.expected))

			for key, expectedVal := range tc.expected {
				actualVal, ok := result[key]
				assert.True(t, ok, "Missing key %v in result", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestManualPHPDeserializeArray_InvalidFormats(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		errorMsg string
	}{
		{"missing_opening_brace", `a:1:i:0;s:5:"hello";}`, "expected '{'"},
		{"missing_array_prefix", `{i:0;s:5:"hello";}`, "expected 'a'"},
		{"invalid_array_size", `a:abc:{i:0;s:5:"hello";}`, "expected array size"},
		{"missing_colon_after_i", `a:1:{i0;s:5:"hello";}`, "expected ':'"},
		{"invalid_key_type", `a:1:{s:1:"a";s:5:"hello";}`, "expected 'i' for key"},
		{"missing_semicolon_after_key", `a:1:{i:0s:5:"hello";}`, "expected ';'"},
		{"invalid_value_type", `a:1:{i:0;i:123;}`, "expected 's' for value"},
		{"string_length_mismatch", `a:1:{i:0;s:10:"short";}`, "string length"},
		{"truncated_string", `a:1:{i:0;s:100:"short`, "exceeds remaining data"},
		{"missing_opening_quote", `a:1:{i:0;s:5:hello";}`, "expected '\"'"},
		{"empty_input", ``, "expected 'a'"},
		// Attacker-controlled length near maxint must error, not panic (pos+strLen overflow).
		{"overflowing_string_length", `a:1:{i:0;s:9223372036854775807:"AB";}`, "exceeds remaining data"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := manualPHPDeserializeArray([]byte(tc.input))
			require.Error(t, err, "expected error containing %q, got no error (result: %v)", tc.errorMsg, result)
			assert.Contains(t, err.Error(), tc.errorMsg)
		})
	}
}

func TestPhpSerializeSortedMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input cloudencrypt.Metadata
		want  string
	}{
		{"nil map", nil, "a:0:{}"},
		{"empty map", cloudencrypt.Metadata{}, "a:0:{}"},
		{"single element", cloudencrypt.Metadata{"key": "value"}, `a:1:{s:3:"key";s:5:"value";}`},
		{
			"multiple elements - sorted by key",
			cloudencrypt.Metadata{"zulu": "last", "alpha": "first", "beta": "second"},
			`a:3:{s:5:"alpha";s:5:"first";s:4:"beta";s:6:"second";s:4:"zulu";s:4:"last";}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, string(phpSerializeSortedMetadata(tt.input)))
		})
	}
}
