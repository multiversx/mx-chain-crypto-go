package interop_test

import (
	"testing"

	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381/interop"
	"github.com/stretchr/testify/require"
)

const g2CompressedSize = 96

// reverse returns a new slice with elements of in reversed.
func reverse(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[len(in)-1-i]
	}
	return out
}

func TestPointBytesFromMcl_Success(t *testing.T) {
	raw := make([]byte, g2CompressedSize)
	for i := range raw {
		raw[i] = byte(i)
	}

	out, err := interop.PointBytesFromMcl(raw)
	require.Nil(t, err)

	expected := reverse(raw)
	expected[0] |= 0x80

	require.Equal(t, expected, out)
}

func TestPointBytesFromMcl_BadLength(t *testing.T) {
	tooShort := make([]byte, 10)
	if _, err := interop.PointBytesFromMcl(tooShort); err == nil {
		t.Error("PointBytesFromMcl should error on short input")
	}

	tooLong := make([]byte, g2CompressedSize+1)
	if _, err := interop.PointBytesFromMcl(tooLong); err == nil {
		t.Error("PointBytesFromMcl should error on long input")
	}
}
