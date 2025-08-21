package lowLevelFeatures

import "errors"

// ErrInvalidCurve signals invalid curveID error
var ErrInvalidCurve = errors.New("invalid curveID provided")

// ErrInvalidPoints signals invalid points error
var ErrInvalidPoints = errors.New("invalid points provided")

// ErrPairingPointsLenShouldMatch signals pairing mismatch error
var ErrPairingPointsLenShouldMatch = errors.New("the number of G1 and G2 points should match for pairing")

// ErrPointsAndScalarsShouldMatch signals points and scalars mismatch error
var ErrPointsAndScalarsShouldMatch = errors.New("the number of points and scalars provided should match")

// ErrInvalidFpElement signals invalid field element error
var ErrInvalidFpElement = errors.New("invalid field element")

// ErrNilOrEmptyInput signals nil or empty input error
var ErrNilOrEmptyInput = errors.New("nil or empty input provided")
