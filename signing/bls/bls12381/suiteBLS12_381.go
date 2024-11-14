package bls12381

import (
	"crypto/cipher"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var log = logger.GetOrCreate("signing/bls12381")

// SuiteBLS12 provides an implementation of the Suite interface for BLS12-381
type SuiteBLS12 struct {
	G1       *groupG1
	G2       *groupG2
	GT       *groupGT
	strSuite string
}

// NewSuiteBLS12 returns a wrapper over a BLS12 curve.
func NewSuiteBLS12() *SuiteBLS12 {
	return &SuiteBLS12{
		G1:       &groupG1{},
		G2:       &groupG2{},
		GT:       &groupGT{},
		strSuite: "BLS12-381 suite",
	}
}

// RandomStream returns a cipher.Stream that returns a key stream
// from crypto/rand.
func (s *SuiteBLS12) RandomStream() cipher.Stream {
	return nil
}

// CreatePoint creates a new point
func (s *SuiteBLS12) CreatePoint() crypto.Point {
	return s.G2.CreatePoint()
}

// String returns the string for the group
func (s *SuiteBLS12) String() string {
	return s.strSuite
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *SuiteBLS12) ScalarLen() int {
	return s.G2.ScalarLen()
}

// CreateScalar creates a new Scalar
func (s *SuiteBLS12) CreateScalar() crypto.Scalar {
	return s.G2.CreateScalar()
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *SuiteBLS12) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
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
func (s *SuiteBLS12) PointLen() int {
	return s.G2.PointLen()
}

// CreateKeyPair returns a pair of private public BLS keys.
// The private key is a scalarInt, while the public key is a Point on G2 curve
func (s *SuiteBLS12) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	var sc crypto.Scalar
	var err error

	sc = s.G2.CreateScalar()
	sc, err = sc.Pick()
	if err != nil {
		log.Error("SuiteBLS12 CreateKeyPair", "error", err.Error())
		return nil, nil
	}

	p := s.G2.CreatePointForScalar(sc)

	return sc, p
}

// GetUnderlyingSuite returns the underlying suite
func (s *SuiteBLS12) GetUnderlyingSuite() interface{} {
	return s
}

// CheckPointValid returns error if the point is not valid (zero is also not valid), otherwise nil
func (s *SuiteBLS12) CheckPointValid(pointBytes []byte) error {
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
func (s *SuiteBLS12) IsInterfaceNil() bool {
	return s == nil
}
