package lowLevelFeatures

import "errors"

var ErrInvalidCurve = errors.New("invalid curveID provided")
var ErrInvalidPoints = errors.New("invalid points provided")
var ErrPairingPointsLenShouldMatch = errors.New("the number of G1 and G2 points should match for pairing")
var ErrPointsAndScalarsShouldMatch = errors.New("the number of points and scalars provided should match")
var ErrInvalidFpElement = errors.New("invalid field element")
