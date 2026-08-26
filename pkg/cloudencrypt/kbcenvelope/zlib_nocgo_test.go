//go:build !cgo

package kbcenvelope

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZlibCompressPHPCompatible_WithoutCGOReturnsClearError(t *testing.T) {
	t.Parallel()

	_, err := zlibCompressPHPCompatible([]byte("a:0:{}"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCGORequired)
}
