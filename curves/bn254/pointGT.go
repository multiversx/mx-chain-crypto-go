package bn254

import (
	"math/big"

	gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// PointGT -
type PointGT struct {
	*gnark.GT
}

// NewPointGT creates a new point on GT initialized with identity
func NewPointGT() *PointGT {
	point := &PointGT{
		GT: &gnark.GT{},
	}

	return point
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (po *PointGT) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(p) {
		return false, crypto.ErrNilParam
	}

	po2, ok := p.(*PointGT)
	if !ok {
		return false, crypto.ErrInvalidParam
	}

	return po.GT.Equal(po2.GT), nil
}

// Clone returns a clone of the receiver.
func (po *PointGT) Clone() crypto.Point {
	po2 := PointGT{
		GT: &gnark.GT{},
	}

	po2.GT = po2.GT.Set(po.GT)

	return &po2
}

// Null returns the neutral identity element.
func (po *PointGT) Null() crypto.Point {
	p := NewPointGT()
	p.GT.C0.B0.SetZero()
	p.GT.C0.B1.SetZero()
	p.GT.C0.B2.SetZero()

	p.GT.C1.B0.SetZero()
	p.GT.C1.B1.SetZero()
	p.GT.C1.B2.SetZero()

	return p
}

// Set sets the receiver equal to another Point p.
func (po *PointGT) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	po1, ok := p.(*PointGT)
	if !ok {
		return crypto.ErrInvalidParam
	}

	po.GT.Set(po1.GT)

	return nil
}

// Add returns the result of adding receiver with Point p given as parameter,
// so that their scalars add homomorphically
func (po *PointGT) Add(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointGT)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointGT{
		GT: &gnark.GT{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.GT = po2.GT.Add(po2.GT, po1.GT)

	return &po2, nil
}

// Sub returns the result of subtracting from receiver the Point p given as parameter,
// so that their scalars subtract homomorphically
func (po *PointGT) Sub(p crypto.Point) (crypto.Point, error) {
	if check.IfNil(p) {
		return nil, crypto.ErrNilParam
	}

	po1, ok := p.(*PointGT)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2 := PointGT{
		GT: &gnark.GT{},
	}

	err := po2.Set(po)
	if err != nil {
		return nil, err
	}

	po2.GT = po2.GT.Sub(po2.GT, po1.GT)

	return &po2, nil
}

// Neg returns the negation of receiver
func (po *PointGT) Neg() crypto.Point {
	po2 := PointGT{
		GT: &gnark.GT{},
	}

	// Multiplicative in GT, we can use inverse
	po2.GT = po2.GT.Inverse(po.GT)

	return &po2
}

// Mul returns the result of multiplying receiver by the scalarInt s.
func (po *PointGT) Mul(s crypto.Scalar) (crypto.Point, error) {
	if check.IfNil(s) {
		return nil, crypto.ErrNilParam
	}

	po2 := PointGT{
		GT: &gnark.GT{},
	}

	s1, ok := s.(*Scalar)
	if !ok {
		return nil, crypto.ErrInvalidParam
	}

	po2.GT = po2.GT.Exp(*po.GT, s1.Scalar.BigInt(&big.Int{}))

	return &po2, nil
}

// Pick returns a new random or pseudo-random Point.
func (po *PointGT) Pick() (crypto.Point, error) {
	var p1, p2 crypto.Point
	var err error

	p1, err = NewPointG1().Pick()
	if err != nil {
		return nil, err
	}

	p2, err = NewPointG2().Pick()
	if err != nil {
		return nil, err
	}

	poG1 := p1.(*PointG1)
	poG2 := p2.(*PointG2)

	po2 := PointGT{
		GT: &gnark.GT{},
	}

	g1Affine := &gnark.G1Affine{}
	g1Affine.FromJacobian(poG1.G1)

	g2Affine := &gnark.G2Affine{}
	g2Affine.FromJacobian(poG2.G2)

	paired, err := gnark.Pair([]gnark.G1Affine{*g1Affine}, []gnark.G2Affine{*g2Affine})
	if err != nil {
		return nil, err
	}

	po2.GT = &paired

	return &po2, nil
}

// GetUnderlyingObj returns the object the implementation wraps
func (po *PointGT) GetUnderlyingObj() interface{} {
	return po.GT
}

// MarshalBinary converts the point into its byte array representation
func (po *PointGT) MarshalBinary() ([]byte, error) {
	return po.GT.Marshal(), nil
}

// UnmarshalBinary reconstructs a point from its byte array representation
func (po *PointGT) UnmarshalBinary(point []byte) error {
	return po.GT.Unmarshal(point)
}

// IsInterfaceNil returns true if there is no value under the interface
func (po *PointGT) IsInterfaceNil() bool {
	return po == nil
}
