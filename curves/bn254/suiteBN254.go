package bn254

import (
	"crypto/cipher"

	gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var log = logger.GetOrCreate("curves/bn254")

// SuiteBN254 provides an implementation of the Suite interface for BN254
type SuiteBN254 struct {
	G1       *groupG1
	G2       *groupG2
	GT       *groupGT
	strSuite string
}

// NewSuiteBN254 returns a wrapper over a BN254 curve.
func NewSuiteBN254() *SuiteBN254 {
	return &SuiteBN254{
		G1:       &groupG1{},
		G2:       &groupG2{},
		GT:       &groupGT{},
		strSuite: "BN254 suite",
	}
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteBN254) RandomStream() cipher.Stream {
	return nil
}

// CreatePoint creates a new point
func (s *SuiteBN254) CreatePoint() crypto.Point {
	return s.G2.CreatePoint()
}

// String returns the string for the group
func (s *SuiteBN254) String() string {
	return s.strSuite
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *SuiteBN254) ScalarLen() int {
	return s.G2.ScalarLen()
}

// CreateScalar creates a new Scalar
func (s *SuiteBN254) CreateScalar() crypto.Scalar {
	return s.G2.CreateScalar()
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *SuiteBN254) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	if check.IfNil(scalar) {
		return nil, crypto.ErrNilPrivateKeyScalar
	}
	sc, ok := scalar.GetUnderlyingObj().(*fr.Element)
	if !ok {
		return nil, crypto.ErrInvalidScalar
	}

	if sc.IsZero() {
		return nil, crypto.ErrInvalidPrivateKey
	}

	point := s.G2.CreatePointForScalar(scalar)

	return point, nil
}

// PointLen returns the max length of point in nb of bytes
func (s *SuiteBN254) PointLen() int {
	return s.G2.PointLen()
}

// CreateKeyPair returns a pair of private public BN254 keys.
// The private key is a scalarInt, while the public key is a Point on G2 curve
func (s *SuiteBN254) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	var sc crypto.Scalar
	var err error

	sc = s.G2.CreateScalar()
	sc, err = sc.Pick()
	if err != nil {
		log.Error("SuiteBN254 CreateKeyPair", "error", err.Error())
		return nil, nil
	}

	p := s.G2.CreatePointForScalar(sc)

	return sc, p
}

// GetUnderlyingSuite returns the underlying suite
func (s *SuiteBN254) GetUnderlyingSuite() interface{} {
	return s
}

// CheckPointValid returns error if the point is not valid (zero is also not valid), otherwise nil
func (s *SuiteBN254) CheckPointValid(pointBytes []byte) error {
	if len(pointBytes) != s.PointLen() {
		return crypto.ErrInvalidParam
	}

	point := s.G2.CreatePoint()
	err := point.UnmarshalBinary(pointBytes)
	if err != nil {
		return err
	}

	pG2, ok := point.GetUnderlyingObj().(*gnark.G2Jac)
	if !ok || !pG2.IsOnCurve() || !pG2.IsInSubGroup() {
		return crypto.ErrInvalidPoint
	}

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *SuiteBN254) IsInterfaceNil() bool {
	return s == nil
}
