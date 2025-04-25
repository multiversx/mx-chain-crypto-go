package interop

import "slices"

func removeFlags(rawPoint []byte) []byte {
	inPlacePoint := append([]byte(nil), rawPoint...)

	slices.Reverse(inPlacePoint)
	inPlacePoint[0] |= 0x80

	return inPlacePoint
}
