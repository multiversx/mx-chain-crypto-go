package ethsig

import (
	"crypto/cipher"
	ethCommon "github.com/ethereum/go-ethereum/common"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var log = logger.GetOrCreate("crypto/signing/ethsig")

var _ crypto.Group = (*Suite)(nil)
var _ crypto.Random = (*Suite)(nil)
var _ crypto.Suite = (*Suite)(nil)

// SuiteName suite string name
const SuiteName = "ethSuite"

type Suite struct{}

// NewSuite returns a new suite
func NewSuite() *Suite {
	return &Suite{}
}

// CreateKeyPair returns nil
func (s *Suite) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	log.Error("suite", "CreateKeyPair not implemented")
	return nil, nil
}

// String returns the name of the suite
func (s *Suite) String() string {
	return SuiteName
}

// ScalarLen returns 0
func (s *Suite) ScalarLen() int {
	log.Error("suite", "ScalarLen not implemented")
	return 0
}

// CreateScalar returns nil
func (s *Suite) CreateScalar() crypto.Scalar {
	log.Error("suite", "CreateScalar not implemented")
	return nil
}

// PointLen returns the max length of point in nb of bytes
func (s *Suite) PointLen() int {
	return ethCommon.AddressLength
}

// CreatePoint creates a new point
func (s *Suite) CreatePoint() crypto.Point {
	return &Point{}
}

// CreatePointForScalar returns error
func (s *Suite) CreatePointForScalar(crypto.Scalar) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// CheckPointValid returns error
func (s *Suite) CheckPointValid([]byte) error {
	return crypto.ErrNotImplemented
}

// RandomStream returns nil
func (s *Suite) RandomStream() cipher.Stream {
	log.Error("suite", "RandomStream not implemented")
	return nil
}

// GetUnderlyingSuite returns nil
func (s *Suite) GetUnderlyingSuite() interface{} {
	log.Error("suite", "RandomStream not implemented")
	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *Suite) IsInterfaceNil() bool {
	return s == nil
}
