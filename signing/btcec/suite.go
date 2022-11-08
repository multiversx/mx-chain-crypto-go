package btcec

import (
	"crypto/cipher"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	logger "github.com/ElrondNetwork/elrond-go-logger"
	"github.com/btcsuite/btcd/btcec"
)

var log = logger.GetOrCreate("crypto/signing/secp256k1")

var _ crypto.Group = (*btcecSuite)(nil)
var _ crypto.Random = (*btcecSuite)(nil)
var _ crypto.Suite = (*btcecSuite)(nil)

// Btcec suite string name
const Btcec = "btcec"

type btcecSuite struct{}

// NewBtcecSuite returns a wrapper over btcec suite
func NewBtcecSuite() *btcecSuite {
	return &btcecSuite{}
}

// CreateKeyPair creates a scalar and a point pair that can be used in asymmetric cryptography
func (s *btcecSuite) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic("could not create btcec key pair: " + err.Error())
	}

	return &btcecScalar{privKey}, &btcecPoint{privKey.PubKey()}
}

// String returns the string for the group
func (s *btcecSuite) String() string {
	return Btcec
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *btcecSuite) ScalarLen() int {
	return btcec.PrivKeyBytesLen
}

// CreateScalar creates a new Scalar
func (s *btcecSuite) CreateScalar() crypto.Scalar {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		panic("could not create secp256k1 key pair: " + err.Error())
	}

	return &btcecScalar{privKey}
}

// PointLen returns the max length of point in nb of bytes
func (s *btcecSuite) PointLen() int {
	return btcec.PubKeyBytesLenCompressed
}

// CreatePoint creates a new point
func (s *btcecSuite) CreatePoint() crypto.Point {
	_, publicKey := s.CreateKeyPair()
	return publicKey
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *btcecSuite) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	privateKey, ok := scalar.GetUnderlyingObj().(btcec.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return &btcecPoint{privateKey.PubKey()}, nil
}

// CheckPointValid returns nil
func (s *btcecSuite) CheckPointValid(pointBytes []byte) error {
	log.Warn("btcecSuite", "CheckPointValid not implemented")

	return crypto.ErrNotImplemented
}

// RandomStream returns nil
func (s *btcecSuite) RandomStream() cipher.Stream {
	log.Warn("btcecSuite", "RandomStream not implemented")

	return nil
}

// GetUnderlyingSuite returns nil
func (s *btcecSuite) GetUnderlyingSuite() interface{} {
	log.Warn("btcecSuite", "GetUnderlyingSuite not implemented")

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *btcecSuite) IsInterfaceNil() bool {
	return s == nil
}
