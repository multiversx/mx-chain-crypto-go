package bls12377

import (
	gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewPointG2(t *testing.T) {
	bG2 := &gnark.G2Jac{}
	_, g2Gen, _, _ := gnark.Generators()
	bG2 = &g2Gen

	pG2 := NewPointG2()
	require.NotNil(t, pG2)

	mclPointG2, ok := pG2.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.True(t, bG2.Equal(mclPointG2))
}

func TestPointG2_Equal(t *testing.T) {
	p1G2 := NewPointG2()
	p2G2 := NewPointG2()

	// new points should be initialized with base point so should be equal
	eq, err := p1G2.Equal(p2G2)
	require.Nil(t, err)
	require.True(t, eq)

	// Make p1G1 different by multiplying it by 2
	scalar := NewScalar()
	scalar.SetInt64(2)
	p1Modified, err := p1G2.Mul(scalar)
	require.Nil(t, err)
	p1G2 = p1Modified.(*PointG2)

	eq, err = p1G2.Equal(p2G2)
	require.Nil(t, err)
	require.False(t, eq)

	grG2 := &groupG2{}
	sc1G2 := grG2.CreateScalar()
	p1 := grG2.CreatePointForScalar(sc1G2)
	p2 := grG2.CreatePointForScalar(sc1G2)

	var ok bool
	p1G2, ok = p1.(*PointG2)
	require.True(t, ok)

	p2G2, ok = p2.(*PointG2)
	require.True(t, ok)

	eq, err = p1G2.Equal(p2G2)
	require.Nil(t, err)
	require.True(t, eq)
}

func TestPointG2_CloneNilShouldPanic(t *testing.T) {
	var p1 *PointG2

	defer func() {
		r := recover()
		if r == nil {
			assert.Fail(t, "should have panicked")
		}
	}()

	_ = p1.Clone()
}

func TestPointG2_Clone(t *testing.T) {
	p1 := NewPointG2()
	p2 := p1.Clone()

	eq, err := p1.Equal(p2)
	require.Nil(t, err)
	require.True(t, eq)
}

func TestPointG2_Null(t *testing.T) {
	p1 := NewPointG2()

	point := p1.Null()
	bls12381Point, ok := point.(*PointG2)
	require.True(t, ok)
	require.True(t, bls12381Point.G2.X.IsZero())
	require.True(t, bls12381Point.G2.Y.IsZero())
	require.True(t, bls12381Point.G2.Z.IsOne())

	bls12381PointNeg := &gnark.G2Jac{}
	bls12381PointNeg = bls12381PointNeg.Neg(bls12381Point.G2)

	// neutral identity point should be equal to it's negation
	ok = bls12381Point.G2.Equal(bls12381PointNeg)
	require.True(t, ok)
}

func TestPointG2_Set(t *testing.T) {
	p1 := NewPointG2()
	p2 := NewPointG2()

	scalar := NewScalar()
	scalar.SetInt64(2)
	p2Modified, err := p2.Mul(scalar)
	require.Nil(t, err)
	p2 = p2Modified.(*PointG2)

	err = p1.Set(p2)
	require.Nil(t, err)
	eq, err := p1.Equal(p2)
	require.Nil(t, err)
	require.True(t, eq)
}

func TestPointG2_AddNilParamShouldErr(t *testing.T) {
	t.Parallel()

	point := NewPointG2()
	point2, err := point.Add(nil)

	assert.Equal(t, crypto.ErrNilParam, err)
	assert.Nil(t, point2)
}

func TestPointG2_AddInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	point := NewPointG2()
	point2 := &mock.PointMock{}
	point3, err := point.Add(point2)

	assert.Equal(t, crypto.ErrInvalidParam, err)
	assert.Nil(t, point3)
}

func TestPointG2_AddOK(t *testing.T) {
	t.Parallel()

	pointG2 := NewPointG2()
	point1, err := pointG2.Pick()
	require.Nil(t, err)

	point2, err := pointG2.Pick()
	require.Nil(t, err)

	sum, err := point1.Add(point2)
	require.Nil(t, err)

	p, err := sum.Sub(point2)
	require.Nil(t, err)

	eq1, _ := point1.Equal(sum)
	eq2, _ := point2.Equal(sum)
	eq3, _ := point1.Equal(p)

	assert.False(t, eq1)
	assert.False(t, eq2)
	assert.True(t, eq3)
}

func TestPointG2_SubNilParamShouldErr(t *testing.T) {
	t.Parallel()

	pointG2 := NewPointG2()
	point2, err := pointG2.Sub(nil)

	assert.Equal(t, crypto.ErrNilParam, err)
	assert.Nil(t, point2)
}

func TestPointG2_SubInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	pointG2 := NewPointG2()
	point2 := &mock.PointMock{}
	point3, err := pointG2.Sub(point2)

	assert.Equal(t, crypto.ErrInvalidParam, err)
	assert.Nil(t, point3)
}

func TestPointG2_SubOK(t *testing.T) {
	t.Parallel()

	pointG2 := NewPointG2()
	point1, err := pointG2.Pick()
	require.Nil(t, err)

	point2, err := pointG2.Pick()
	require.Nil(t, err)

	sum, _ := point1.Add(point2)
	point3, err := sum.Sub(point2)
	assert.Nil(t, err)

	eq, err := point3.Equal(point1)
	assert.Nil(t, err)
	assert.True(t, eq)
}

func TestPointG2_Neg(t *testing.T) {
	point1 := NewPointG2()

	point2 := point1.Neg()
	point3 := point2.Neg()

	assert.NotEqual(t, point1, point2)
	assert.NotEqual(t, point2, point3)
	assert.Equal(t, point1, point3)
}

func TestPointG2_MulNilParamShouldErr(t *testing.T) {
	t.Parallel()

	point := NewPointG2()
	res, err := point.Mul(nil)

	assert.Equal(t, crypto.ErrNilParam, err)
	assert.Nil(t, res)
}

func TestPointG2_MulInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	point := NewPointG2()
	scalar := &mock.ScalarMock{}
	res, err := point.Mul(scalar)

	assert.Equal(t, crypto.ErrInvalidParam, err)
	assert.Nil(t, res)
}

func TestPointG2_MulOK(t *testing.T) {
	t.Parallel()

	pointG2 := NewPointG2()
	s := NewScalar()
	scalar, err := s.Pick()
	require.Nil(t, err)

	res, err := pointG2.Mul(scalar)

	require.Nil(t, err)
	require.NotNil(t, res)
	require.NotEqual(t, pointG2, res)

	grG2 := &groupG2{}
	point2 := grG2.CreatePointForScalar(scalar)
	eq, err := res.Equal(point2)
	require.Nil(t, err)
	require.True(t, eq)
}

func TestPointG2_PickOK(t *testing.T) {
	t.Parallel()

	point1 := NewPointG2()
	point2, err1 := point1.Pick()
	eq, err2 := point1.Equal(point2)

	assert.Nil(t, err1)
	assert.Nil(t, err2)
	assert.False(t, eq)
}

func TestPointG2_GetUnderlyingObj(t *testing.T) {
	t.Parallel()

	point1 := NewPointG2()
	p := point1.GetUnderlyingObj()

	assert.NotNil(t, p)
}

func TestPointG2_MarshalBinary(t *testing.T) {
	t.Parallel()

	point1 := NewPointG2()
	pointBytes, err := point1.MarshalBinary()

	assert.Nil(t, err)
	assert.NotNil(t, pointBytes)
}

func TestPointG2_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	point1, _ := NewPointG2().Pick()
	pointBytes, _ := point1.MarshalBinary()

	point2 := NewPointG2()
	err := point2.UnmarshalBinary(pointBytes)
	eq, _ := point1.Equal(point2)

	assert.Nil(t, err)
	assert.True(t, eq)
}

func TestPointG2_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var point *PointG2

	require.True(t, check.IfNil(point))
	point = NewPointG2()
	require.False(t, check.IfNil(point))
}
