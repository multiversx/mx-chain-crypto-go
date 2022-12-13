package x25519

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"golang.org/x/crypto/curve25519"
)

// X25519 is the string representations of the X25519 scheme
const X25519 = "X25519"

type suiteX25519 struct{}

func NewX25519() *suiteX25519 {
	return &suiteX25519{}
}

// CreateKeyPair returns a pair of X25519 keys
//
//	If an error occurs, it will be logged, and the function will return nil/nil.
func (s *suiteX25519) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	randomness := rand.Reader

	sk := make([]byte, curve25519.ScalarSize)
	if _, err := randomness.Read(sk); err != nil {
		log.Error(fmt.Sprintf("suiteX25519.CreateKeyPair: error in reading randomness, %s", err.Error()))
		return nil, nil
	}

	pubKey, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		log.Error(fmt.Sprintf("suiteX25519.CreateKeyPair: error in generating public key, %s", err.Error()))
		return nil, nil
	}

	return &x25519Scalar{sk}, &x25519Point{pubKey}
}

// CreatePoint returns a newly created public key which is a point on curve25519
func (s *suiteX25519) CreatePoint() crypto.Point {
	_, publicKey := s.CreateKeyPair()
	return publicKey
}

// CreatePointForScalar returns a Point that is the representation of a public key corresponding
//
//	to the provided Scalar in the x25519 scheme
func (s *suiteX25519) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	privateKey, ok := scalar.GetUnderlyingObj().(PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	publicKey, err := privateKey.Public()
	if err != nil {
		return nil, err
	}

	return &x25519Point{publicKey}, nil
}

// String returns the string for the group
func (s *suiteX25519) String() string {
	return X25519
}

// ScalarLen returns the length of the x25519 private key
func (s *suiteX25519) ScalarLen() int {
	return curve25519.ScalarSize
}

// CreateScalar creates a new Scalar which represents the x25519 private key
func (s *suiteX25519) CreateScalar() crypto.Scalar {
	sk := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(sk); err != nil {
		log.Error(fmt.Sprintf("suiteX25519.CreateScalar: error in reading randomness, %s", err.Error()))
		return nil
	}

	return &x25519Scalar{sk}
}

// PointLen returns the number of bytes of the x25519 public key
func (s *suiteX25519) PointLen() int {
	return curve25519.PointSize
}

// GetUnderlyingSuite returns nothing because this is not a wrapper over another suite implementation
func (s *suiteX25519) GetUnderlyingSuite() interface{} {
	log.Warn("suiteX25519",
		"message", "calling GetUnderlyingSuite for suiteX25519 which has no underlying suite")

	return nil
}

// CheckPointValid -
func (s *suiteX25519) CheckPointValid(pointBytes []byte) error {
	if len(pointBytes) != s.PointLen() {
		return crypto.ErrInvalidParam
	}

	point := s.CreatePoint()
	return point.UnmarshalBinary(pointBytes)
	if err != nil {
		return err
	}

	return nil
}

// RandomStream returns nothing - TODO: Remove this
func (s *suiteX25519) RandomStream() cipher.Stream {
	log.Debug("suiteX25519",
		"message", "calling RandomStream for suiteX25519 - this function should not be used")

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *suiteX25519) IsInterfaceNil() bool {
	return s == nil
}
