package kbcenvelope

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackendError(t *testing.T) {
	t.Parallel()

	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	be := &BackendError{Cause: fmt.Errorf("KMS decrypt failed: %w", netErr)}

	wrapped := fmt.Errorf("decryption failed: %w", be)

	var got *BackendError
	require.ErrorAs(t, wrapped, &got, "BackendError must be discoverable via errors.As")

	var ne net.Error
	require.ErrorAs(t, wrapped, &ne, "net.Error must remain reachable through BackendError")

	assert.Contains(t, be.Error(), "connection refused")
}

func TestBackendError_NotMatchedByPlainError(t *testing.T) {
	t.Parallel()

	var got *BackendError
	assert.NotErrorAs(t, errors.New("AES decryption failed"), &got,
		"a plain local error must not be classified as a BackendError")
}
