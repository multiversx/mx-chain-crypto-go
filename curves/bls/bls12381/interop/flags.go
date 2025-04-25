package interop

import (
	"errors"
	"slices"
)

const (
	g2CompressedSize = 96
	compressedBit    = 0x80
)

// PointBytesFromMcl adds the compression flag to a point from MCL since in non-eth mode it is not used,
// but we always know we are using the compressed version
func PointBytesFromMcl(rawPoint []byte) ([]byte, error) {
	if len(rawPoint) != g2CompressedSize {
		return nil, errors.New("interop: raw MCL point must be 96 bytes")
	}

	be := reverseBytes(rawPoint)
	markCompressed(be)

	return be, nil
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	slices.Reverse(out)

	return out
}

func markCompressed(buf []byte) {
	buf[0] |= compressedBit
}
