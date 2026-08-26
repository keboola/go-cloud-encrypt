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
//
// Split into one function per grammar production (header / key / string value) purely to keep
// each one's branching manageable — the grammar itself, and every error message, is unchanged.
func manualPHPDeserializeArray(data []byte) (map[any]any, error) {
	result := make(map[any]any)

	pos, err := parsePHPArrayHeader(data)
	if err != nil {
		return nil, err
	}

	for pos < len(data) && data[pos] != '}' {
		key, next, err := parsePHPArrayKey(data, pos)
		if err != nil {
			return nil, err
		}

		value, next, err := parsePHPArrayStringValue(data, next)
		if err != nil {
			return nil, err
		}

		result[key] = value
		pos = next
	}

	// The loop above exits either on a '}' terminator or on running out of data first — the
	// latter means a truncated input, which must be rejected rather than accepted with
	// whatever partial set of members happened to be read.
	if _, err := expectByte(data, pos, '}', "expected '}' at position %d"); err != nil {
		return nil, err
	}

	return result, nil
}

// expectByte requires data[pos] == want and returns pos+1, or a *fmt.Errorf(errFmt, pos) if
// data is exhausted or the byte differs. errFmt must take exactly one %d (the position).
func expectByte(data []byte, pos int, want byte, errFmt string) (int, error) {
	if pos >= len(data) || data[pos] != want {
		return 0, fmt.Errorf(errFmt, pos) //nolint:govet // errFmt is always a caller-supplied literal with one %d
	}

	return pos + 1, nil
}

// scanDigits consumes a run of ASCII digits starting at pos and reports whether it read at
// least one.
func scanDigits(data []byte, pos int) (int, bool) {
	end := pos
	for end < len(data) && data[end] >= '0' && data[end] <= '9' {
		end++
	}

	return end, end != pos
}

// readFixedLengthString reads exactly n bytes at pos, binary-safe. n is attacker-controlled
// (it arrives inside a user's configuration value), so it's checked against the bytes actually
// remaining rather than as pos+n, which would overflow for a declared length near maxint and
// wrap negative, slipping past a naive guard and panicking on the slice.
func readFixedLengthString(data []byte, pos, n int) (string, int, error) {
	if n < 0 || n > len(data)-pos {
		return "", 0, fmt.Errorf("string length %d exceeds remaining data at position %d", n, pos)
	}

	return string(data[pos : pos+n]), pos + n, nil
}

// parsePHPArrayHeader consumes "a:N:{" and returns the position of the first member (or '}').
func parsePHPArrayHeader(data []byte) (int, error) {
	pos, err := expectByte(data, 0, 'a', "expected 'a' at position %d")
	if err != nil {
		return 0, err
	}

	pos, err = expectByte(data, pos, ':', "expected ':' at position %d")
	if err != nil {
		return 0, err
	}

	sizeEnd, ok := scanDigits(data, pos)
	if !ok {
		return 0, fmt.Errorf("expected array size at position %d", pos)
	}

	pos, err = expectByte(data, sizeEnd, ':', "expected ':' after array size at position %d")
	if err != nil {
		return 0, err
	}

	return expectByte(data, pos, '{', "expected '{' at position %d")
}

// parsePHPArrayKey consumes "i:X;" starting at pos and returns the key and the position after it.
func parsePHPArrayKey(data []byte, pos int) (int64, int, error) {
	pos, err := expectByte(data, pos, 'i', "expected 'i' for key at position %d")
	if err != nil {
		return 0, 0, err
	}

	pos, err = expectByte(data, pos, ':', "expected ':' after 'i' at position %d")
	if err != nil {
		return 0, 0, err
	}

	keyEnd, ok := scanDigits(data, pos)
	if !ok {
		return 0, 0, fmt.Errorf("expected integer key at position %d", pos)
	}

	var key int64
	if _, err := fmt.Sscanf(string(data[pos:keyEnd]), "%d", &key); err != nil {
		return 0, 0, fmt.Errorf("expected integer key at position %d: %w", pos, err)
	}

	pos, err = expectByte(data, keyEnd, ';', "expected ';' after key at position %d")
	if err != nil {
		return 0, 0, err
	}

	return key, pos, nil
}

// parsePHPArrayStringValue consumes "s:L:"<L bytes>";" starting at pos, binary-safe, and
// returns the decoded value and the position after it.
func parsePHPArrayStringValue(data []byte, pos int) (string, int, error) {
	pos, err := expectByte(data, pos, 's', "expected 's' for value at position %d")
	if err != nil {
		return "", 0, err
	}

	pos, err = expectByte(data, pos, ':', "expected ':' after 's' at position %d")
	if err != nil {
		return "", 0, err
	}

	lenEnd, ok := scanDigits(data, pos)
	if !ok {
		return "", 0, fmt.Errorf("expected string length at position %d", pos)
	}

	var strLen int
	if _, err := fmt.Sscanf(string(data[pos:lenEnd]), "%d", &strLen); err != nil {
		return "", 0, fmt.Errorf("expected string length at position %d: %w", pos, err)
	}

	pos, err = expectByte(data, lenEnd, ':', "expected ':' after string length at position %d")
	if err != nil {
		return "", 0, err
	}

	pos, err = expectByte(data, pos, '"', "expected '\"' at position %d")
	if err != nil {
		return "", 0, err
	}

	value, pos, err := readFixedLengthString(data, pos, strLen)
	if err != nil {
		return "", 0, err
	}

	pos, err = expectByte(data, pos, '"', "expected closing '\"' at position %d")
	if err != nil {
		return "", 0, err
	}

	pos, err = expectByte(data, pos, ';', "expected ';' after value at position %d")
	if err != nil {
		return "", 0, err
	}

	return value, pos, nil
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
