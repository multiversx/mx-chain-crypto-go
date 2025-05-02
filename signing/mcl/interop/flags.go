package interop

import (
	"errors"
	"slices"

	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381"
)

const (
	g2CompressedSize   = 96
	g2UnCompressedSize = 192
	yOddMask           = 0x80
)

// PointBytesFromGnark converts a point from BLS to MCL format
func PointBytesFromGnark(rawPoint []byte) ([]byte, error) {
	if len(rawPoint) != g2UnCompressedSize {
		return nil, errors.New("interop: raw BLS point must be 192 bytes")
	}

	// TODO: Find a cleaner way to test Y sign without re-assembling the gnark point
	gnarkPoint := bls12381.NewPointG2()
	_ = gnarkPoint.UnmarshalBinary(rawPoint)
	isYodd := gnarkPoint.G2.Y.LexicographicallyLargest()

	X := rawPoint[:g2CompressedSize]
	X = reverseBytes(X)

	if isYodd {
		X[g2CompressedSize-1] |= yOddMask
	} else {
		X[g2CompressedSize-1] &= 0x7f
	}

	return X, nil
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	slices.Reverse(out)

	return out
}
