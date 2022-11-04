package ecdsa

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

// TODO: handler not implemented methods properly

var _ crypto.Group = (*suiteEcdsa)(nil)
var _ crypto.Random = (*suiteEcdsa)(nil)
var _ crypto.Suite = (*suiteEcdsa)(nil)

const ECDSA = "ecdsa"

const privateKeySize = 32
const publicKeySize = 33

type suiteEcdsa struct{}

// NewEcdsa returns a wrapper over ecdsa
func NewEcdsa() *suiteEcdsa {
	return &suiteEcdsa{}
}

// CreateKeyPair creates a scalar and a point pair that can be used in asymmetric cryptography
func (s *suiteEcdsa) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		panic("could not create ecdsa key pair: " + err.Error())
	}

	return &ecdsaScalar{*privateKey}, &ecdsaPoint{privateKey.PublicKey}
}

// String returns the string for the group
func (s *suiteEcdsa) String() string {
	return ECDSA
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *suiteEcdsa) ScalarLen() int {
	return privateKeySize
}

// CreateScalar creates a new Scalar
func (s *suiteEcdsa) CreateScalar() crypto.Scalar {
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		panic("could not create ecdsa key pair: " + err.Error())
	}

	return &ecdsaScalar{*privateKey}
}

// PointLen returns the max length of point in nb of bytes
func (s *suiteEcdsa) PointLen() int {
	return publicKeySize
}

// CreatePoint creates a new point
func (s *suiteEcdsa) CreatePoint() crypto.Point {
	_, publicKey := s.CreateKeyPair()
	return publicKey
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *suiteEcdsa) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	privateKey, ok := scalar.GetUnderlyingObj().(ecdsa.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	publicKey, ok := privateKey.Public().(ecdsa.PublicKey)
	if !ok {
		return nil, crypto.ErrGeneratingPubFromPriv
	}

	return &ecdsaPoint{publicKey}, nil
}

// RandomStream returns a cipher.Stream that produces a
// cryptographically random key stream. The stream must
// tolerate being used in multiple goroutines.
func (s *suiteEcdsa) RandomStream() cipher.Stream {
	panic("not implemented") // TODO: Implement
}

// CheckPointValid returns nil if point is valid otherwise error. Zero is reported also as invalid
func (s *suiteEcdsa) CheckPointValid(pointBytes []byte) error {
	panic("not implemented") // TODO: Implement
}

// GetUnderlyingSuite returns the library suite that crypto.Suite wraps
func (s *suiteEcdsa) GetUnderlyingSuite() interface{} {
	panic("not implemented") // TODO: Implement
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *suiteEcdsa) IsInterfaceNil() bool {
	return s == nil
}
