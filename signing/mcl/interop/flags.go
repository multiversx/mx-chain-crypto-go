package interop

import (
	"errors"
	"slices"
)

const (
	g2CompressedSize = 96
	compressedBit    = 0x80
	infiniteBit      = 0x40
	signBit          = 0x20
)

// PointBytesFromBls converts a point from BLS to MCL format
func PointBytesFromBls(rawPoint []byte) ([]byte, error) {
	if len(rawPoint) != g2CompressedSize {
		return nil, errors.New("interop: raw BLS point must be 96 bytes")
	}

	be := reverseBytes(rawPoint)
	removeFlags(be)

	return be, nil
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	slices.Reverse(out)

	return out
}

func removeFlags(buf []byte) {
	buf[g2CompressedSize-1] &^= compressedBit
	buf[g2CompressedSize-1] &^= infiniteBit
	buf[g2CompressedSize-1] &^= signBit
}
