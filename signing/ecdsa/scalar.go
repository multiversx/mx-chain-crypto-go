package ecdsa

import (
	"fmt"

	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

var _ crypto.Scalar = (*ecdsaScalar)(nil)

type ecdsaScalar struct {
	btcec.PrivateKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *ecdsaScalar) GetUnderlyingObj() interface{} {
	return e.PrivateKey
}

// MarshalBinary transforms the Scalar into a byte array
func (e *ecdsaScalar) MarshalBinary() ([]byte, error) {
	return e.PrivateKey.Serialize(), nil
}

// UnmarshalBinary recreates the Scalar from a byte array
func (e *ecdsaScalar) UnmarshalBinary(key []byte) error {
	if len(key) != btcec.PrivKeyBytesLen {
		return fmt.Errorf("expected key size to be %d", btcec.PrivKeyBytesLen)
	}
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), key)

	e.PrivateKey = *privKey

	return nil
}

// Equal tests if receiver is equal with the scalar s given as parameter.
// Both scalars need to be derived from the same Group
func (e *ecdsaScalar) Equal(s crypto.Scalar) (bool, error) {
	if check.IfNil(s) {
		return false, crypto.ErrNilParam
	}

	privateKey, ok := s.GetUnderlyingObj().(btcec.PrivateKey)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return privateKey.Equal(e.PrivateKey), nil
}

// Set sets the receiver to Scalar s given as parameter
func (e *ecdsaScalar) Set(s crypto.Scalar) error {
	if check.IfNil(s) {
		return crypto.ErrNilParam
	}

	privateKey, ok := s.GetUnderlyingObj().(btcec.PrivateKey)
	if !ok {
		return crypto.ErrInvalidPrivateKey
	}

	e.PrivateKey = privateKey

	return nil
}

// Clone creates a new Scalar with same value as receiver
func (e *ecdsaScalar) Clone() crypto.Scalar {
	if e == nil {
		return nil
	}

	es2 := *e
	return &es2
}

// SetInt64 sets the receiver to a small integer value v given as parameter
func (e *ecdsaScalar) SetInt64(v int64) {
	panic("not implemented") // TODO: Implement
}

// Zero returns the the additive identity (0)
func (e *ecdsaScalar) Zero() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// Add returns the modular sum of receiver with scalar s given as parameter
func (e *ecdsaScalar) Add(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Sub returns the modular difference between receiver and scalar s given as parameter
func (e *ecdsaScalar) Sub(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Neg returns the modular negation of receiver
func (e *ecdsaScalar) Neg() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// One returns the multiplicative identity (1)
func (e *ecdsaScalar) One() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// Mul returns the modular product of receiver with scalar s given as parameter
func (e *ecdsaScalar) Mul(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Div returns the modular division between receiver and scalar s given as parameter
func (e *ecdsaScalar) Div(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Inv returns the modular inverse of scalar s given as parameter
func (e *ecdsaScalar) Inv(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Pick returns a fresh random or pseudo-random scalar
func (e *ecdsaScalar) Pick() (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// SetBytes sets the scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
func (e *ecdsaScalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *ecdsaScalar) IsInterfaceNil() bool {
	return e == nil
}
