package bls12381

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// Scalar -
type Scalar struct {
	Scalar *fr.Element
}

func NewScalar() *Scalar {
	scalar := &Scalar{Scalar: &fr.Element{}}
	scalar.setRandom()

	for scalar.Scalar.IsOne() || scalar.Scalar.IsZero() {
		scalar.setRandom()
	}

	return scalar
}

// Equal tests if receiver is equal with the scalarInt s given as parameter.
// Both scalars need to be derived from the same Group
func (sc *Scalar) Equal(s crypto.Scalar) (bool, error) {
	if check.IfNil(s) {
		return false, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return false, crypto.ErrInvalidParam
	}

	areEqual := sc.Scalar.Equal(s2.Scalar)

	return areEqual, nil
}

// Set sets the receiver to Scalar s given as parameter
func (sc *Scalar) Set(s crypto.Scalar) error {
	if check.IfNil(s) {
		return crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return crypto.ErrInvalidParam
	}

	return sc.Scalar.SetBytesCanonical(s2.Scalar.Marshal())
}

// Clone creates a new Scalar with same value as receiver
func (sc *Scalar) Clone() crypto.Scalar {
	scalar := &Scalar{
		Scalar: &fr.Element{},
	}

	scalar.Scalar.SetBytes(sc.Scalar.Marshal())

	return scalar
}

// SetInt64 sets the receiver to a small integer value v given as parameter
func (sc *Scalar) SetInt64(v int64) {
	sc.Scalar.SetInt64(v)
}

// Zero returns the additive identity (0)
func (sc *Scalar) Zero() crypto.Scalar {
	s := Scalar{
		Scalar: &fr.Element{},
	}
	s.Scalar.SetZero()

	return &s
}

// Add returns the modular sum of receiver with scalar s given as parameter
func (sc *Scalar) Add(s crypto.Scalar) (crypto.Scalar, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	s1 := &Scalar{
		Scalar: &fr.Element{},
	}

	s1.Scalar.Add(sc.Scalar, s2.Scalar)

	return s1, nil
}

// Sub returns the modular difference between receiver and scalar s given as parameter
func (sc *Scalar) Sub(s crypto.Scalar) (crypto.Scalar, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	s1 := &Scalar{
		Scalar: &fr.Element{},
	}

	s1.Scalar.Sub(sc.Scalar, s2.Scalar)

	return s1, nil
}

// Neg returns the modular negation of receiver
func (sc *Scalar) Neg() crypto.Scalar {
	s := Scalar{
		Scalar: &fr.Element{},
	}

	s.Scalar.Neg(sc.Scalar)

	return &s
}

// One returns the multiplicative identity (1)
func (sc *Scalar) One() crypto.Scalar {
	s := Scalar{
		Scalar: &fr.Element{},
	}
	s.Scalar.SetOne()

	return &s
}

// Mul returns the modular product of receiver with scalar s given as parameter
func (sc *Scalar) Mul(s crypto.Scalar) (crypto.Scalar, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	s1 := Scalar{
		Scalar: &fr.Element{},
	}

	s1.Scalar.Mul(sc.Scalar, s2.Scalar)

	return &s1, nil
}

// Div returns the modular division between receiver and scalar s given as parameter
func (sc *Scalar) Div(s crypto.Scalar) (crypto.Scalar, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	s1 := Scalar{
		Scalar: &fr.Element{},
	}

	s1.Scalar.Div(sc.Scalar, s2.Scalar)

	return &s1, nil
}

// Inv returns the modular inverse of scalar s given as parameter
func (sc *Scalar) Inv(s crypto.Scalar) (crypto.Scalar, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	s2, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	s1 := Scalar{
		Scalar: &fr.Element{},
	}

	s1.Scalar.Inverse(s2.Scalar)

	return &s1, nil
}

// Pick returns a fresh random or pseudo-random scalar
// For the mock set X to the original scalar.X *2
func (sc *Scalar) Pick() (crypto.Scalar, error) {
	s1 := Scalar{
		Scalar: &fr.Element{},
	}

	_, err := s1.Scalar.SetRandom()
	if err != nil {
		return nil, err
	}

	for s1.Scalar.IsOne() || s1.Scalar.IsZero() {
		_, err = s1.Scalar.SetRandom()
		if err != nil {
			return nil, err
		}
	}

	return &s1, nil
}

// SetBytes sets the scalar from a byte-slice,
// reducing if necessary to the appropriate modulus.
func (sc *Scalar) SetBytes(s []byte) (crypto.Scalar, error) {
	if len(s) == 0 {
		return nil, crypto.ErrNilParam
	}

	s1 := sc.Clone()
	s2, ok := s1.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidScalar
	}

	err := s2.Scalar.SetBytesCanonical(s)
	if err != nil {
		return nil, err
	}

	return s1, nil
}

// GetUnderlyingObj returns the object the implementation wraps
func (sc *Scalar) GetUnderlyingObj() interface{} {
	return sc.Scalar
}

// MarshalBinary transforms the Scalar into a byte array
func (sc *Scalar) MarshalBinary() ([]byte, error) {
	return sc.Scalar.Marshal(), nil
}

// UnmarshalBinary recreates the Scalar from a byte array
func (sc *Scalar) UnmarshalBinary(val []byte) error {
	return sc.Scalar.SetBytesCanonical(val)
}

// IsInterfaceNil returns true if there is no value under the interface
func (sc *Scalar) IsInterfaceNil() bool {
	return sc == nil
}

func (sc *Scalar) setRandom() {
	_, err := sc.Scalar.SetRandom()
	if err != nil {
		panic("BLS12381 cannot read from rand to create a new scalar")
	}
}
