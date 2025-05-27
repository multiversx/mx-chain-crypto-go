package bls12381

import (
	"math/big"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// PointG1 -
type PointG1 struct {
	G1 *gnark.G1Jac
}

func NewPointG1() *PointG1 {
	point := &PointG1{
		G1: &gnark.G1Jac{},
	}

	g1Gen, _, _, _ := gnark.Generators()
	point.G1 = &g1Gen

	return point
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (po *PointG1) Equal(p crypto.Point) (bool, error) {
	if p == nil {
		return false, crypto.ErrNilParam
	}

	po2, ok := p.(*PointG1)
	if !ok {
		return false, crypto.ErrInvalidParam
	}

	return po.G1.Equal(po2.G1), nil
}

// Clone returns a clone of the receiver.
func (po *PointG1) Clone() crypto.Point {
	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	po2.G1 = po2.G1.Set(po.G1)

	return &po2
}

// Null returns the neutral identity element.
func (po *PointG1) Null() crypto.Point {
	p := &PointG1{
		G1: &gnark.G1Jac{},
	}

	p.G1.Z.SetZero()
	p.G1.X.SetOne()
	p.G1.Y.SetOne()

	return p
}

// Set sets the receiver equal to another Point p.
func (po *PointG1) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	po1, ok := p.(*PointG1)
	if !ok {
		return crypto.ErrInvalidParam
	}

	po.G1.Set(po1.G1)

	return nil
}

// Add returns the result of adding receiver with Point p given as parameter,
// so that their scalars add homomorphically
func (po *PointG1) Add(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointG1)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.G1 = po2.G1.AddAssign(po1.G1)

	return &po2, nil
}

// Sub returns the result of subtracting from receiver the Point p given as parameter,
// so that their scalars subtract homomorphically
func (po *PointG1) Sub(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointG1)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.G1 = po2.G1.SubAssign(po1.G1)

	return &po2, nil
}

// Neg returns the negation of receiver
func (po *PointG1) Neg() crypto.Point {
	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	po2.G1 = po2.G1.Neg(po.G1)

	return &po2
}

// Mul returns the result of multiplying receiver by the scalarInt s.
func (po *PointG1) Mul(s crypto.Scalar) (crypto.Point, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	s1, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2.G1 = po2.G1.ScalarMultiplication(po.G1, s1.Scalar.BigInt(&big.Int{}))

	return &po2, nil
}

// Pick returns a new random or pseudo-random Point.
func (po *PointG1) Pick() (crypto.Point, error) {
	scalar := NewScalar()

	po2 := PointG1{
		G1: &gnark.G1Jac{},
	}

	po2.G1 = po2.G1.ScalarMultiplication(po.G1, scalar.Scalar.BigInt(&big.Int{}))

	return &po2, nil
}

// GetUnderlyingObj returns the object the implementation wraps
func (po *PointG1) GetUnderlyingObj() interface{} {
	return po.G1
}

// MarshalBinary converts the point into its byte array representation
func (po *PointG1) MarshalBinary() ([]byte, error) {
	affinePoint := &gnark.G1Affine{}
	affinePoint.FromJacobian(po.G1)

	return affinePoint.Marshal(), nil
}

// UnmarshalBinary reconstructs a point from its byte array representation
func (po *PointG1) UnmarshalBinary(point []byte) error {
	affinePoint := &gnark.G1Affine{}
	err := affinePoint.Unmarshal(point)
	if err != nil {
		return err
	}

	po.G1 = po.G1.FromAffine(affinePoint)
	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (po *PointG1) IsInterfaceNil() bool {
	return po == nil
}
