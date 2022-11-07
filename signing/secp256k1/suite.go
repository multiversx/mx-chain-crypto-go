package secp256k1

import (
	"crypto/cipher"
	"crypto/rand"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	libp2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
)

// TODO: handler not implemented methods properly

var _ crypto.Group = (*secp256k1Suite)(nil)
var _ crypto.Random = (*secp256k1Suite)(nil)
var _ crypto.Suite = (*secp256k1Suite)(nil)

const Secp256k1 = "secp256k1"

const privateKeySize = 32
const publicKeySize = 33

type secp256k1Suite struct{}

// NewSecp256k1 returns a wrapper over ecdsa
func NewSecp256k1() *secp256k1Suite {
	return &secp256k1Suite{}
}

// CreateKeyPair creates a scalar and a point pair that can be used in asymmetric cryptography
func (s *secp256k1Suite) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	privKey, publicKey, err := libp2pCrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		panic("could not create secp256k1 key pair: " + err.Error())
	}

	return &secp256k1Scalar{privKey}, &secp256k1Point{publicKey}
}

// String returns the string for the group
func (s *secp256k1Suite) String() string {
	return Secp256k1
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *secp256k1Suite) ScalarLen() int {
	return privateKeySize
}

// CreateScalar creates a new Scalar
func (s *secp256k1Suite) CreateScalar() crypto.Scalar {
	privKey, _, err := libp2pCrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		panic("could not create secp256k1 key pair: " + err.Error())
	}

	return &secp256k1Scalar{privKey}
}

// PointLen returns the max length of point in nb of bytes
func (s *secp256k1Suite) PointLen() int {
	return publicKeySize
}

// CreatePoint creates a new point
func (s *secp256k1Suite) CreatePoint() crypto.Point {
	_, publicKey := s.CreateKeyPair()
	return publicKey
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *secp256k1Suite) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	privateKey, ok := scalar.GetUnderlyingObj().(libp2pCrypto.PrivKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return &secp256k1Point{privateKey.GetPublic()}, nil
}

// RandomStream returns a cipher.Stream that produces a
// cryptographically random key stream. The stream must
// tolerate being used in multiple goroutines.
func (s *secp256k1Suite) RandomStream() cipher.Stream {
	panic("not implemented") // TODO: Implement
}

// CheckPointValid returns nil if point is valid otherwise error. Zero is reported also as invalid
func (s *secp256k1Suite) CheckPointValid(pointBytes []byte) error {
	panic("not implemented") // TODO: Implement
}

// GetUnderlyingSuite returns the library suite that crypto.Suite wraps
func (s *secp256k1Suite) GetUnderlyingSuite() interface{} {
	panic("not implemented") // TODO: Implement
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *secp256k1Suite) IsInterfaceNil() bool {
	return s == nil
}
