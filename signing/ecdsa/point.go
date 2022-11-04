package ecdsa

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
)

var _ crypto.Point = (*ecdsaPoint)(nil)

type ecdsaPoint struct {
	ecdsa.PublicKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *ecdsaPoint) GetUnderlyingObj() interface{} {
	return e.PublicKey
}

// MarshalBinary transforms the Point into a byte array
func (e *ecdsaPoint) MarshalBinary() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(e.PublicKey)
	if err != nil {
		return nil, err
	}

	return pubKeyBytes, nil
}

// UnmarshalBinary recreates the Point from a byte array
func (e *ecdsaPoint) UnmarshalBinary(key []byte) error {
	genericPubKey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return err
	}

	pubKey := genericPubKey.(ecdsa.PublicKey)

	e.PublicKey = pubKey

	return nil
}

// Clone returns a clone of the receiver.
func (e *ecdsaPoint) Clone() crypto.Point {
	if e == nil {
		return nil
	}

	es2 := *e
	return &es2
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (e *ecdsaPoint) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(e) {
		return false, crypto.ErrNilParam
	}

	publicKey, ok := e.GetUnderlyingObj().(ecdsa.PublicKey)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return publicKey.Equal(e.PublicKey), nil
}

// Set sets the receiver equal to another Point p.
func (e *ecdsaPoint) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	point, ok := p.(*ecdsaPoint)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	e.PublicKey = point.PublicKey

	return nil
}

// Null returns the neutral identity element.
func (e *ecdsaPoint) Null() crypto.Point {
	panic("not implemented") // TODO: Implement
}

// Add returns the result of adding receiver with Point p given as parameter,
// so that their scalars add homomorphically
func (e *ecdsaPoint) Add(p crypto.Point) (crypto.Point, error) {
	panic("not implemented") // TODO: Implement
}

// Sub returns the result of subtracting from receiver the Point p given as parameter,
// so that their scalars subtract homomorphically
func (e *ecdsaPoint) Sub(p crypto.Point) (crypto.Point, error) {
	panic("not implemented") // TODO: Implement
}

// Neg returns the negation of receiver
func (e *ecdsaPoint) Neg() crypto.Point {
	panic("not implemented") // TODO: Implement
}

// Mul returns the result of multiplying receiver by the scalar s.
func (e *ecdsaPoint) Mul(s crypto.Scalar) (crypto.Point, error) {
	panic("not implemented") // TODO: Implement
}

// Pick returns a fresh random or pseudo-random Point.
func (e *ecdsaPoint) Pick() (crypto.Point, error) {
	panic("not implemented") // TODO: Implement
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *ecdsaPoint) IsInterfaceNil() bool {
	return e == nil
}
