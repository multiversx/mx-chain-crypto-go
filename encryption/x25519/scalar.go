package x25519

import (
	"bytes"
	"crypto/sha512"
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"golang.org/x/crypto/curve25519"
)

var _ crypto.Scalar = (*x25519Scalar)(nil)

type PrivateKey []byte

func (p *PrivateKey) Public() (PublicKey, error) {
	pubKey, err := curve25519.X25519(*p, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

type x25519Scalar struct {
	PrivateKey
}

// Equal checks if the underlying private key inside the scalar objects contain the same bytes
func (x *x25519Scalar) Equal(s crypto.Scalar) (bool, error) {
	privateKey, err := x.getPrivateKeyFromScalar(s)
	if err != nil {
		return false, err
	}

	return bytes.Equal(privateKey, x.PrivateKey), nil
}

// Set sets the underlying private key inside the scalar to the private key of the provided scalar
func (x *x25519Scalar) Set(s crypto.Scalar) error {
	privateKey, err := x.getPrivateKeyFromScalar(s)
	if err != nil {
		return err
	}

	x.PrivateKey = privateKey

	return nil
}

// FromX25519 converts a scalar from ed25519 specs to a x25519 one
func (x *x25519Scalar) FromX25519(scalarBytes []byte) error {
	h := sha512.New()
	h.Write(scalarBytes[:curve25519.ScalarSize])
	scalar := h.Sum(nil)

	x.PrivateKey = scalar

	return nil
}

// Clone creates a new Scalar with same value as receiver
func (x *x25519Scalar) Clone() crypto.Scalar {
	scalarBytes := make([]byte, len(x.PrivateKey))
	copy(scalarBytes, x.PrivateKey)

	return &x25519Scalar{scalarBytes}
}

// GetUnderlyingObj returns the object the implementation wraps
func (x *x25519Scalar) GetUnderlyingObj() interface{} {
	err := isKeyValid(x.PrivateKey)
	if err != nil {
		log.Error("x25519Scalar",
			"message", "GetUnderlyingObj invalid private key construction")
		return nil
	}

	return x.PrivateKey
}

// MarshalBinary encodes the receiver into a binary form and returns the result.
func (x *x25519Scalar) MarshalBinary() ([]byte, error) {
	err := isKeyValid(x.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x.PrivateKey, nil
}

// UnmarshalBinary decodes a scalar from its byte array representation and sets the receiver to this value
func (x *x25519Scalar) UnmarshalBinary(s []byte) error {
	err := isKeyValid(s)
	if err != nil {
		return err
	}

	x.PrivateKey = s

	return nil
}

// SetInt64 is not needed for this use case, should be removed if possible
func (x *x25519Scalar) SetInt64(_ int64) {
	log.Error("x25519Scalar",
		"message", "SetInt64 for x25519Scalar is not implemented, should not be called")
}

// Zero is not needed for this use case, should be removed if possible
func (x *x25519Scalar) Zero() crypto.Scalar {
	log.Error("x25519Scalar",
		"message", "SetInt64 for x25519Scalar is not implemented, should not be called")

	return nil
}

// Add is not needed for this use case, should be removed if possible
func (x *x25519Scalar) Add(_ crypto.Scalar) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Add for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Sub is not needed for this use case, should be removed if possible
func (x *x25519Scalar) Sub(_ crypto.Scalar) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Sub for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Neg is not needed for this use case, should be removed if possible
func (x *x25519Scalar) Neg() crypto.Scalar {
	log.Error("x25519Scalar",
		"message", "Neg for x25519Scalar is not implemented, should not be called")

	return nil
}

// One is not needed for this use case, should be removed if possible
func (x *x25519Scalar) One() crypto.Scalar {
	log.Error("x25519Scalar",
		"message", "One for x25519Scalar is not implemented, should not be called")

	return nil
}

// Mul returns the modular product of receiver with scalar s given as parameter
func (x *x25519Scalar) Mul(_ crypto.Scalar) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Mul for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Div returns the modular division between receiver and scalar s given as parameter
func (x *x25519Scalar) Div(_ crypto.Scalar) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Div for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Inv returns the modular inverse of scalar s given as parameter
func (x *x25519Scalar) Inv(_ crypto.Scalar) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Inv for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// Pick returns a fresh random or pseudo-random scalar
func (x *x25519Scalar) Pick() (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "Pick for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// SetBytes sets the scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
func (x *x25519Scalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	log.Error("x25519Scalar",
		"message", "SetBytes for x25519Scalar is not implemented, should not be called")

	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (x *x25519Scalar) IsInterfaceNil() bool {
	return x == nil
}

func (x *x25519Scalar) getPrivateKeyFromScalar(s crypto.Scalar) (PrivateKey, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	privateKey, ok := s.GetUnderlyingObj().(PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return privateKey, nil
}

func isKeyValid(key PrivateKey) error {
	if len(key) != curve25519.ScalarSize {
		return crypto.ErrWrongPrivateKeySize
	}

	return nil
}
