package ethsig

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

var _ crypto.Point = (*Point)(nil)

type Point struct {
	bytes []byte
}

// GetUnderlyingObj returns the object the implementation wraps
func (p *Point) GetUnderlyingObj() interface{} {
	return p.bytes
}

// MarshalBinary transforms the Point into a byte array
func (p *Point) MarshalBinary() ([]byte, error) {
	return p.bytes, nil
}

// UnmarshalBinary recreates the Point from a byte array
func (p *Point) UnmarshalBinary(key []byte) error {
	p.assignBytes(key)
	return nil
}

// Clone returns a clone of the receiver.
func (p *Point) Clone() crypto.Point {
	if p == nil {
		return nil
	}

	cloned := &Point{}
	cloned.assignBytes(p.bytes)
	return cloned
}

// Equal tests if receiver is equal with the Point p given as parameter. Both Points need to be derived from the same Group
func (p *Point) Equal(other crypto.Point) (bool, error) {
	if check.IfNil(other) {
		return false, crypto.ErrNilParam
	}

	otherPoint, ok := other.(*Point)
	if !ok {
		return false, crypto.ErrInvalidPublicKey
	}

	return bytes.Equal(otherPoint.bytes, p.bytes), nil
}

// Set sets the receiver equal to another Point p.
func (p *Point) Set(other crypto.Point) error {
	if check.IfNil(other) {
		return crypto.ErrNilParam
	}

	otherPoint, ok := other.(*Point)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	p.assignBytes(otherPoint.bytes)
	return nil
}

// Null returns nil
func (p *Point) Null() crypto.Point {
	log.Error("point", "Null not implemented")
	return nil
}

// Add returns error
func (p *Point) Add(crypto.Point) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Sub returns error
func (p *Point) Sub(crypto.Point) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Neg returns nil
func (p *Point) Neg() crypto.Point {
	log.Error("point", "Neg not implemented")
	return nil
}

// Mul returns error
func (p *Point) Mul(crypto.Scalar) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Pick returns error
func (p *Point) Pick() (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (p *Point) IsInterfaceNil() bool {
	return p == nil
}

func (p *Point) assignBytes(bytes []byte) {
	p.bytes = make([]byte, len(bytes))
	copy(p.bytes, bytes)
}
