package interop

import (
	"errors"
	"slices"
)

const (
	g2CompressedSize = 96
	compressedMask   = 0x80
	yOddMask         = 0x20
)

// PointBytesFromMcl adds the compression flag to a point from MCL since in non-eth mode it is not used,
// but we always know we are using the compressed version. Also, MCL sets the Y odd flag as the MSB
// of the last byte which we need to use for compression, so we add that as the 3rd MSB in that
// byte as Ganrk expects it
func PointBytesFromMcl(rawPoint []byte) ([]byte, error) {
	if len(rawPoint) != g2CompressedSize {
		return nil, errors.New("interop: raw MCL point must be 96 bytes")
	}

	isYodd := (rawPoint[g2CompressedSize-1] >> 7) != 0
	// fmt.Println("MCL Point is odd", isYodd)
	be := reverseBytes(rawPoint)

	markCompressed(be)
	if isYodd {
		markOdd(be)
	}

	return be, nil
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	slices.Reverse(out)

	return out
}

func markCompressed(buf []byte) {
	buf[0] |= compressedMask
}

func markOdd(buf []byte) {
	buf[0] |= yOddMask
}
