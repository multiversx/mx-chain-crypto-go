package btcec

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

var _ crypto.Scalar = (*btcecScalar)(nil)

type btcecScalar struct {
	Scalar *btcec.PrivateKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *btcecScalar) GetUnderlyingObj() interface{} {
	return e.Scalar
}

// MarshalBinary transforms the Scalar into a byte array
func (e *btcecScalar) MarshalBinary() ([]byte, error) {
	return e.Scalar.Serialize(), nil
}

// UnmarshalBinary recreates the Scalar from a byte array
func (e *btcecScalar) UnmarshalBinary(key []byte) error {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), key)
	e.Scalar = privKey

	return nil
}

// Equal tests if receiver is equal with the scalar s given as parameter.
// Both scalars need to be derived from the same Group
func (e *btcecScalar) Equal(s crypto.Scalar) (bool, error) {
	if check.IfNil(s) {
		return false, crypto.ErrNilParam
	}

	privateKey, ok := s.(*btcecScalar)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return e.Scalar.Equal(privateKey), nil
}

// Set sets the receiver to Scalar s given as parameter
func (e *btcecScalar) Set(s crypto.Scalar) error {
	if check.IfNil(s) {
		return crypto.ErrNilParam
	}

	scalar, ok := s.(*btcecScalar)
	if !ok {
		return crypto.ErrInvalidPrivateKey
	}

	e.Scalar = scalar.Scalar

	return nil
}

// Clone creates a new Scalar with same value as receiver
func (e *btcecScalar) Clone() crypto.Scalar {
	if e == nil {
		return nil
	}

	s := &btcecScalar{
		Scalar: e.Scalar,
	}

	return s
}

// SetInt64 does nothing
func (e *btcecScalar) SetInt64(v int64) {
	log.Warn("btcecScalar", "SetInt64 not implemented")
}

// Zero returns nil
func (e *btcecScalar) Zero() crypto.Scalar {
	log.Warn("btcecScalar", "Zero not implemented")

	return nil
}

// Add returns nil
func (e *btcecScalar) Add(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Add not implemented")

	return nil, crypto.ErrNotImplemented
}

// Sub returns nil
func (e *btcecScalar) Sub(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Sub not implemented")

	return nil, crypto.ErrNotImplemented
}

// Neg returns nil
func (e *btcecScalar) Neg() crypto.Scalar {
	log.Warn("btcecScalar", "Neg not implemented")

	return nil
}

// One returns nil
func (e *btcecScalar) One() crypto.Scalar {
	log.Warn("btcecScalar", "One not implemented")

	return nil
}

// Mul returns nil
func (e *btcecScalar) Mul(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Mul not implemented")

	return nil, crypto.ErrNotImplemented
}

// Div returns nil
func (e *btcecScalar) Div(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Div not implemented")

	return nil, crypto.ErrNotImplemented
}

// Inv returns nil
func (e *btcecScalar) Inv(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Inv not implemented")

	return nil, crypto.ErrNotImplemented
}

// Pick returns nil
func (e *btcecScalar) Pick() (crypto.Scalar, error) {
	log.Warn("btcecScalar", "Pick not implemented")

	return nil, crypto.ErrNotImplemented
}

// SetBytes returns nil
func (e *btcecScalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	log.Warn("btcecScalar", "SetBytes not implemented")

	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *btcecScalar) IsInterfaceNil() bool {
	return e == nil
}
