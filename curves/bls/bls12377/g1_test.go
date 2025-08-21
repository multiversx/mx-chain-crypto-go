package bls12377

import (
	gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestGroupG1_String(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	str := grG1.String()
	require.Equal(t, "BLS12-377 G1", str)
}

func TestGroupG1_ScalarLen(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	x := grG1.ScalarLen()
	require.Equal(t, fr.Bytes, x)
}

func TestGroupG1_PointLen(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	x := grG1.PointLen()
	require.Equal(t, 48, x)
}

func TestGroupG1_CreatePoint(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	g1Gen, _, _, _ := gnark.Generators()
	point := &PointG1{
		G1: &g1Gen,
	}

	x := grG1.CreatePoint()
	require.NotNil(t, x)
	bls12381Point, ok := x.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bls12381Point.IsOnCurve())
	require.Equal(t, point.G1, bls12381Point)
}

func TestGroupG1_CreateScalar(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	sc := grG1.CreateScalar()
	require.NotNil(t, sc)

	bls12381Scalar, ok := sc.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bls12381Scalar.IsZero())
	require.False(t, bls12381Scalar.IsOne())
}

func TestGroupG1_CreatePointForScalar(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bls12381Scalar.IsZero())
	require.False(t, bls12381Scalar.IsOne())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	bls12381PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bls12381PointG1.IsOnCurve())

	bG1 := NewPointG1().G1
	var scalarBigInt big.Int
	bls12381Scalar.BigInt(&scalarBigInt)
	computedG1 := bG1.ScalarMultiplication(bG1, &scalarBigInt)

	require.True(t, bls12381PointG1.Equal(computedG1))
}

func TestGroupG1_CreatePointForScalarZero(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	scalar.SetInt64(0)
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bls12381Scalar.IsZero())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	bls12381PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bls12381PointG1.Z.IsZero())
	require.True(t, bls12381PointG1.IsOnCurve())

	bG1 := NewPointG1().G1
	var scalarBigInt big.Int
	bls12381Scalar.BigInt(&scalarBigInt)
	computedG1 := bG1.ScalarMultiplication(bG1, &scalarBigInt)

	require.True(t, bls12381PointG1.Equal(computedG1))

}

func TestGroupG1_CreatePointForScalarOne(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	scalar.SetInt64(1)
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bls12381Scalar.IsOne())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	baseG1 := NewPointG1().G1
	bls12381PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bls12381PointG1.Equal(baseG1))
}

func TestGroupG1_CreatePointForScalarNil(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}
	pG1 := grG1.CreatePointForScalar(nil)
	require.Equal(t, nil, pG1)
}

func TestGroupG1_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var grG1 *groupG1

	require.True(t, grG1.IsInterfaceNil())
	grG1 = &groupG1{}
	require.False(t, grG1.IsInterfaceNil())
}
