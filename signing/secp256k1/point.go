package secp256k1

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	libp2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
)

var _ crypto.Point = (*secp256k1Point)(nil)

type secp256k1Point struct {
	libp2pCrypto.PubKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *secp256k1Point) GetUnderlyingObj() interface{} {
	return e.PubKey
}

// MarshalBinary transforms the Point into a byte array
func (e *secp256k1Point) MarshalBinary() ([]byte, error) {
	return e.PubKey.Raw()
}

// UnmarshalBinary recreates the Point from a byte array
func (e *secp256k1Point) UnmarshalBinary(key []byte) error {
	pubKey, err := libp2pCrypto.UnmarshalSecp256k1PublicKey(key)
	if err != nil {
		return err
	}

	e.PubKey = pubKey

	return nil
}

// Clone returns a clone of the receiver.
func (e *secp256k1Point) Clone() crypto.Point {
	if e == nil {
		return nil
	}

	es2 := *e
	return &es2
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (e *secp256k1Point) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(e) {
		return false, crypto.ErrNilParam
	}

	publicKey, ok := e.GetUnderlyingObj().(libp2pCrypto.PubKey)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return publicKey.Equals(e.PubKey), nil
}

// Set sets the receiver equal to another Point p.
func (e *secp256k1Point) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	point, ok := p.(*secp256k1Point)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	e.PubKey = point.PubKey

	return nil
}

// Null returns nil
func (e *secp256k1Point) Null() crypto.Point {
	log.Warn("secp256k1Point", "Nill not implemented")

	return nil
}

// Add returns nil
func (e *secp256k1Point) Add(p crypto.Point) (crypto.Point, error) {
	log.Warn("secp256k1Point", "Add not implemented")

	return nil, nil
}

// Sub returns nil
func (e *secp256k1Point) Sub(p crypto.Point) (crypto.Point, error) {
	log.Warn("secp256k1Point", "Sub not implemented")

	return nil, nil
}

// Neg returns nil
func (e *secp256k1Point) Neg() crypto.Point {
	log.Warn("secp256k1Point", "Neg not implemented")

	return nil
}

// Mul returns nil
func (e *secp256k1Point) Mul(s crypto.Scalar) (crypto.Point, error) {
	log.Warn("secp256k1Point", "Mul not implemented")

	return nil, nil
}

// Pick returns nil
func (e *secp256k1Point) Pick() (crypto.Point, error) {
	log.Warn("secp256k1Point", "Pick not implemented")

	return nil, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *secp256k1Point) IsInterfaceNil() bool {
	return e == nil
}
