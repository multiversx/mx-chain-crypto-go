package x25519

import (
	"bytes"
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
)

type PublicKey []byte

type x25519Point struct {
	PublicKey
}

// Equal tests if receiver is equal with the Point p given as parameter.
func (x *x25519Point) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(p) {
		return false, crypto.ErrNilParam
	}

	x25519P, ok := p.(*x25519Point)
	if !ok {
		return false, crypto.ErrInvalidPublicKey
	}

	return bytes.Equal(x.PublicKey, x25519P.PublicKey), nil
}

// GetUnderlyingObj returns the object the implementation wraps
func (x *x25519Point) GetUnderlyingObj() interface{} {
	return x.PublicKey
}

// MarshalBinary converts the point into its byte array representation
func (x *x25519Point) MarshalBinary() ([]byte, error) {
	return x.PublicKey, nil
}

// UnmarshalBinary reconstructs a point from its byte array representation
func (x *x25519Point) UnmarshalBinary(point []byte) error {
	x.PublicKey = point
	return nil
}

// Set sets the receiver equal to another Point p.
func (x *x25519Point) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	point, ok := p.(*x25519Point)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	x.PublicKey = point.PublicKey
	return nil
}

// Clone returns a clone of the receiver.
func (x *x25519Point) Clone() crypto.Point {
	publicKeyBytes := make([]byte, len(x.PublicKey))
	copy(publicKeyBytes, x.PublicKey)

	return &x25519Point{publicKeyBytes}
}

// Null is not needed for this use case, should be removed if possible
func (x *x25519Point) Null() crypto.Point {
	log.Error("x25519Point",
		"message", "Null for x25519Point is not implemented, should not be called")

	return nil
}

// Base is not needed for this use case, should be removed if possible
func (x *x25519Point) Base() crypto.Point {
	log.Error("x25519Point",
		"message", "Base for x25519Point is not implemented, should not be called")

	return nil
}

// Add is not needed for this use case, should be removed if possible
func (x *x25519Point) Add(_ crypto.Point) (crypto.Point, error) {
	log.Error("x25519Point",
		"message", "Add for x25519Point is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Sub is not needed for this use case, should be removed if possible
func (x *x25519Point) Sub(_ crypto.Point) (crypto.Point, error) {
	log.Error("x25519Point",
		"message", "Sub for x25519Point is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Neg is not needed for this use case, should be removed if possible
func (x *x25519Point) Neg() crypto.Point {
	log.Error("x25519Point",
		"message", "Neg for x25519Point is not implemented, should not be called")

	return nil
}

// Mul is not needed for this use case, should be removed if possible
func (x *x25519Point) Mul(_ crypto.Scalar) (crypto.Point, error) {
	log.Error("x25519Point",
		"message", "Mul for x25519Point is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Pick is not needed for this use case, should be removed if possible
func (x *x25519Point) Pick() (crypto.Point, error) {
	log.Error("x25519Point",
		"message", "Pick for x25519Point is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (x *x25519Point) IsInterfaceNil() bool {
	return x == nil
}
