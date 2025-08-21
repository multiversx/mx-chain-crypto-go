package lowLevelFeatures

// PointAdd performs addition on two points of a specified curve
func PointAdd(curveID ID, group GroupID, point1Bytes, point2Bytes []byte) ([]byte, error) {
	handler, ok := EcRegistry[ECParams{curveID, group}]
	if !ok {
		return nil, ErrInvalidCurve
	}

	return handler.Add(point1Bytes, point2Bytes)
}

// ScalarMul performs scalar multiplication on the specified curve
func ScalarMul(curveID ID, group GroupID, point, scalar []byte) ([]byte, error) {
	handler, ok := EcRegistry[ECParams{curveID, group}]
	if !ok {
		return nil, ErrInvalidCurve
	}

	return handler.Mul(point, scalar)
}

// MultiExp performs multi exponent on the specified curve
func MultiExp(curveID ID, group GroupID, points [][]byte, scalars [][]byte) ([]byte, error) {
	handler, ok := EcRegistry[ECParams{curveID, group}]
	if !ok {
		return nil, ErrInvalidCurve
	}

	return handler.MultiExp(points, scalars)
}

// MapToCurve performs map to curve operation on the specified curve
func MapToCurve(curveID ID, group GroupID, element []byte) ([]byte, error) {
	handler, ok := EcRegistry[ECParams{curveID, group}]
	if !ok {
		return nil, ErrInvalidCurve
	}

	return handler.MapToCurve(element)
}

// PairingCheck performs pairing check operation on the specified curve
func PairingCheck(curveID ID, pointsG1, pointsG2 [][]byte) (bool, error) {
	handler, ok := PairingRegistry[curveID]
	if !ok {
		return false, ErrInvalidCurve
	}

	return handler.PairingCheck(pointsG1, pointsG2)
}
