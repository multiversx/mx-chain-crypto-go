package bls12377

import (
	"math/big"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// PointG2 -
type PointG2 struct {
	G2 *gnark.G2Jac
}

// NewPointG2 creates a new point on G2 initialized with base point
func NewPointG2() *PointG2 {
	point := &PointG2{
		G2: &gnark.G2Jac{},
	}

	_, g2Gen, _, _ := gnark.Generators()
	point.G2 = &g2Gen

	return point
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (po *PointG2) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(p) {
		return false, crypto.ErrNilParam
	}

	po2, ok := p.(*PointG2)
	if !ok {
		return false, crypto.ErrInvalidParam
	}

	return po.G2.Equal(po2.G2), nil
}

// Clone returns a clone of the receiver.
func (po *PointG2) Clone() crypto.Point {
	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	po2.G2 = po2.G2.Set(po.G2)

	return &po2
}

// Null returns the neutral identity element.
func (po *PointG2) Null() crypto.Point {
	p := &PointG2{
		G2: &gnark.G2Jac{},
	}

	p.G2.Z.SetOne()
	p.G2.X.SetZero()
	p.G2.Y.SetZero()

	return p
}

// Set sets the receiver equal to another Point p.
func (po *PointG2) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	po1, ok := p.(*PointG2)
	if !ok {
		return crypto.ErrInvalidParam
	}

	po.G2.Set(po1.G2)

	return nil
}

// Add returns the result of adding receiver with Point p given as parameter,
// so that their scalars add homomorphically
func (po *PointG2) Add(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointG2)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.G2 = po2.G2.AddAssign(po1.G2)

	return &po2, nil
}

// Sub returns the result of subtracting from receiver the Point p given as parameter,
// so that their scalars subtract homomorphically
func (po *PointG2) Sub(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointG2)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.G2 = po2.G2.SubAssign(po1.G2)

	return &po2, nil
}

// Neg returns the negation of receiver
func (po *PointG2) Neg() crypto.Point {
	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	po2.G2 = po2.G2.Neg(po.G2)

	return &po2
}

// Mul returns the result of multiplying receiver by the scalarInt s.
func (po *PointG2) Mul(s crypto.Scalar) (crypto.Point, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	s1, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2.G2 = po2.G2.ScalarMultiplication(po.G2, s1.Scalar.BigInt(&big.Int{}))

	return &po2, nil
}

// Pick returns a new random or pseudo-random Point.
func (po *PointG2) Pick() (crypto.Point, error) {
	scalar := NewScalar()

	po2 := PointG2{
		G2: &gnark.G2Jac{},
	}

	po2.G2 = po2.G2.ScalarMultiplication(po.G2, scalar.Scalar.BigInt(&big.Int{}))

	return &po2, nil
}

// GetUnderlyingObj returns the object the implementation wraps
func (po *PointG2) GetUnderlyingObj() interface{} {
	return po.G2
}

// MarshalBinary converts the point into its byte array representation
func (po *PointG2) MarshalBinary() ([]byte, error) {
	affinePoint := &gnark.G2Affine{}
	affinePoint.FromJacobian(po.G2)

	return affinePoint.Marshal(), nil
}

// UnmarshalBinary reconstructs a point from its byte array representation
func (po *PointG2) UnmarshalBinary(point []byte) error {
	affinePoint := &gnark.G2Affine{}
	err := affinePoint.Unmarshal(point)
	if err != nil {
		return err
	}

	po.G2 = po.G2.FromAffine(affinePoint)
	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (po *PointG2) IsInterfaceNil() bool {
	return po == nil
}
