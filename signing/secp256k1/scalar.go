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
	privKey, err := libp2pCrypto.UnmarshalSecp256k1PrivateKey(key)
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

// SetInt64 does nothing
func (e *secp256k1Scalar) SetInt64(v int64) {
	log.Warn("secp256k1Scalar", "SetInt64 not implemented")
}

// Zero returns nil
func (e *secp256k1Scalar) Zero() crypto.Scalar {
	log.Warn("secp256k1Scalar", "Zero not implemented")

	return nil
}

// Add returns nil
func (e *secp256k1Scalar) Add(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Add not implemented")

	return nil, nil
}

// Sub returns nil
func (e *secp256k1Scalar) Sub(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Sub not implemented")

	return nil, nil
}

// Neg returns nil
func (e *secp256k1Scalar) Neg() crypto.Scalar {
	log.Warn("secp256k1Scalar", "Neg not implemented")

	return nil
}

// One returns nil
func (e *secp256k1Scalar) One() crypto.Scalar {
	log.Warn("secp256k1Scalar", "One not implemented")

	return nil
}

// Mul returns nil
func (e *secp256k1Scalar) Mul(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Mul not implemented")

	return nil, nil
}

// Div returns nil
func (e *secp256k1Scalar) Div(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Div not implemented")

	return nil, nil
}

// Inv returns nil
func (e *secp256k1Scalar) Inv(s crypto.Scalar) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Inv not implemented")

	return nil, nil
}

// Pick returns nil
func (e *secp256k1Scalar) Pick() (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "Pick not implemented")

	return nil, nil
}

// SetBytes returns nil
func (e *secp256k1Scalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	log.Warn("secp256k1Scalar", "SetBytes not implemented")

	return nil, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *secp256k1Scalar) IsInterfaceNil() bool {
	return e == nil
}
