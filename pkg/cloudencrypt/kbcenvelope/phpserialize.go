package kbcenvelope

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// manualPHPDeserializeArray deserializes a PHP array of the shape a:N:{<key><value>...} with
// binary-safe string values: i:X; (integer) or s:L:"<L bytes>"; (string, may contain any byte
// including embedded NUL/quote/brace, so it cannot be parsed with a generic tokenizer).
//
// This is a hand-rolled deserializer, not the general-purpose github.com/elliotchance/phpserialize
// library, because that library mis-reads large binary strings (off by one byte). It is only
// used for the outer envelope array (payload + key/secret-name/secret-version), whose string
// members are exactly this kind of binary-safe blob.
func manualPHPDeserializeArray(data []byte) (map[any]any, error) {
	result := make(map[any]any)
	pos := 0

	if pos >= len(data) || data[pos] != 'a' {
		return nil, fmt.Errorf("expected 'a' at position %d", pos)
	}

	pos++

	if pos >= len(data) || data[pos] != ':' {
		return nil, fmt.Errorf("expected ':' at position %d", pos)
	}

	pos++

	sizeEnd := pos
	for sizeEnd < len(data) && data[sizeEnd] >= '0' && data[sizeEnd] <= '9' {
		sizeEnd++
	}

	if sizeEnd == pos {
		return nil, fmt.Errorf("expected array size at position %d", pos)
	}

	pos = sizeEnd

	if pos >= len(data) || data[pos] != ':' {
		return nil, fmt.Errorf("expected ':' after array size at position %d", pos)
	}

	pos++

	if pos >= len(data) || data[pos] != '{' {
		return nil, fmt.Errorf("expected '{' at position %d", pos)
	}

	pos++

	for pos < len(data) && data[pos] != '}' {
		if pos >= len(data) || data[pos] != 'i' {
			return nil, fmt.Errorf("expected 'i' for key at position %d", pos)
		}

		pos++

		if pos >= len(data) || data[pos] != ':' {
			return nil, fmt.Errorf("expected ':' after 'i' at position %d", pos)
		}

		pos++

		keyEnd := pos
		for keyEnd < len(data) && data[keyEnd] >= '0' && data[keyEnd] <= '9' {
			keyEnd++
		}

		if keyEnd == pos {
			return nil, fmt.Errorf("expected integer key at position %d", pos)
		}

		var key int64
		if _, err := fmt.Sscanf(string(data[pos:keyEnd]), "%d", &key); err != nil {
			return nil, fmt.Errorf("expected integer key at position %d: %w", pos, err)
		}

		pos = keyEnd

		if pos >= len(data) || data[pos] != ';' {
			return nil, fmt.Errorf("expected ';' after key at position %d", pos)
		}

		pos++

		if pos >= len(data) || data[pos] != 's' {
			return nil, fmt.Errorf("expected 's' for value at position %d", pos)
		}

		pos++

		if pos >= len(data) || data[pos] != ':' {
			return nil, fmt.Errorf("expected ':' after 's' at position %d", pos)
		}

		pos++

		lenEnd := pos
		for lenEnd < len(data) && data[lenEnd] >= '0' && data[lenEnd] <= '9' {
			lenEnd++
		}

		if lenEnd == pos {
			return nil, fmt.Errorf("expected string length at position %d", pos)
		}

		var strLen int
		if _, err := fmt.Sscanf(string(data[pos:lenEnd]), "%d", &strLen); err != nil {
			return nil, fmt.Errorf("expected string length at position %d: %w", pos, err)
		}

		pos = lenEnd

		if pos >= len(data) || data[pos] != ':' {
			return nil, fmt.Errorf("expected ':' after string length at position %d", pos)
		}

		pos++

		if pos >= len(data) || data[pos] != '"' {
			return nil, fmt.Errorf("expected '\"' at position %d", pos)
		}

		pos++

		// Compared against the bytes remaining rather than as pos+strLen, which overflows for
		// a declared length near maxint and wraps negative, slipping past the guard and
		// panicking on the slice below. strLen is attacker-controlled (it arrives inside a
		// user's configuration value).
		if strLen < 0 || strLen > len(data)-pos {
			return nil, fmt.Errorf("string length %d exceeds remaining data at position %d", strLen, pos)
		}

		value := string(data[pos : pos+strLen])
		pos += strLen

		if pos >= len(data) || data[pos] != '"' {
			return nil, fmt.Errorf("expected closing '\"' at position %d", pos)
		}

		pos++

		if pos >= len(data) || data[pos] != ';' {
			return nil, fmt.Errorf("expected ';' after value at position %d", pos)
		}

		pos++

		result[key] = value
	}

	return result, nil
}

// phpSerializeSortedMetadata serializes Metadata to PHP's array format with keys sorted
// ascending (matching PHP's ksort()), used to build the Google KMS AAD. An empty/nil map
// serializes to PHP's empty-array literal.
func phpSerializeSortedMetadata(metadata cloudencrypt.Metadata) []byte {
	if len(metadata) == 0 {
		return []byte("a:0:{}")
	}

	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var buf bytes.Buffer

	buf.WriteString("a:")
	buf.WriteString(strconv.Itoa(len(metadata)))
	buf.WriteString(":{")

	for _, k := range keys {
		v := metadata[k]

		buf.WriteString("s:")
		buf.WriteString(strconv.Itoa(len(k)))
		buf.WriteString(":\"")
		buf.WriteString(k)
		buf.WriteString("\";")

		buf.WriteString("s:")
		buf.WriteString(strconv.Itoa(len(v)))
		buf.WriteString(":\"")
		buf.WriteString(v)
		buf.WriteString("\";")
	}

	buf.WriteString("}")

	return buf.Bytes()
}
