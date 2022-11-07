package secp256k1

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	libp2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
)

var _ crypto.Scalar = (*secp256k1Scalar)(nil)

type secp256k1Scalar struct {
	libp2pCrypto.PrivKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *secp256k1Scalar) GetUnderlyingObj() interface{} {
	return e.PrivKey
}

// MarshalBinary transforms the Scalar into a byte array
func (e *secp256k1Scalar) MarshalBinary() ([]byte, error) {
	return e.PrivKey.Raw()
}

// UnmarshalBinary recreates the Scalar from a byte array
func (e *secp256k1Scalar) UnmarshalBinary(key []byte) error {
	privKey, err := libp2pCrypto.UnmarshalEd25519PrivateKey(key)
	if err != nil {
		return err
	}

	e.PrivKey = privKey

	return nil
}

// Equal tests if receiver is equal with the scalar s given as parameter.
// Both scalars need to be derived from the same Group
func (e *secp256k1Scalar) Equal(s crypto.Scalar) (bool, error) {
	if check.IfNil(s) {
		return false, crypto.ErrNilParam
	}

	privateKey, ok := s.GetUnderlyingObj().(libp2pCrypto.PrivKey)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return privateKey.Equals(e.PrivKey), nil
}

// Set sets the receiver to Scalar s given as parameter
func (e *secp256k1Scalar) Set(s crypto.Scalar) error {
	if check.IfNil(s) {
		return crypto.ErrNilParam
	}

	privateKey, ok := s.GetUnderlyingObj().(libp2pCrypto.PrivKey)
	if !ok {
		return crypto.ErrInvalidPrivateKey
	}

	e.PrivKey = privateKey

	return nil
}

// Clone creates a new Scalar with same value as receiver
func (e *secp256k1Scalar) Clone() crypto.Scalar {
	if e == nil {
		return nil
	}

	es2 := *e
	return &es2
}

// SetInt64 sets the receiver to a small integer value v given as parameter
func (e *secp256k1Scalar) SetInt64(v int64) {
	panic("not implemented") // TODO: Implement
}

// Zero returns the the additive identity (0)
func (e *secp256k1Scalar) Zero() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// Add returns the modular sum of receiver with scalar s given as parameter
func (e *secp256k1Scalar) Add(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Sub returns the modular difference between receiver and scalar s given as parameter
func (e *secp256k1Scalar) Sub(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Neg returns the modular negation of receiver
func (e *secp256k1Scalar) Neg() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// One returns the multiplicative identity (1)
func (e *secp256k1Scalar) One() crypto.Scalar {
	panic("not implemented") // TODO: Implement
}

// Mul returns the modular product of receiver with scalar s given as parameter
func (e *secp256k1Scalar) Mul(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Div returns the modular division between receiver and scalar s given as parameter
func (e *secp256k1Scalar) Div(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Inv returns the modular inverse of scalar s given as parameter
func (e *secp256k1Scalar) Inv(s crypto.Scalar) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// Pick returns a fresh random or pseudo-random scalar
func (e *secp256k1Scalar) Pick() (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// SetBytes sets the scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
func (e *secp256k1Scalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	panic("not implemented") // TODO: Implement
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *secp256k1Scalar) IsInterfaceNil() bool {
	return e == nil
}
