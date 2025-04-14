package bn254

import (
	gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupG1_String(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	str := grG1.String()
	require.Equal(t, str, "BN254 G1")
}

func TestGroupG1_ScalarLen(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	x := grG1.ScalarLen()
	require.Equal(t, 32, x)
}

func TestGroupG1_PointLen(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	x := grG1.PointLen()
	require.Equal(t, 32, x)
}

func TestGroupG1_CreatePoint(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}
	point := &PointG1{
		G1: &gnark.G1Jac{},
	}

	g1Gen, _, _, _ := gnark.Generators()
	point.G1 = &g1Gen

	x := grG1.CreatePoint()
	require.NotNil(t, x)
	bn254Point, ok := x.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.Equal(t, point.G1, bn254Point)
}

func TestGroupG1_CreateScalar(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	sc := grG1.CreateScalar()
	require.NotNil(t, sc)

	mclScalar, ok := sc.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, mclScalar.IsZero())
	require.False(t, mclScalar.IsOne())
}

func TestGroupG1_CreatePointForScalar(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	bn254Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bn254Scalar.IsZero())
	require.False(t, bn254Scalar.IsOne())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	bn254PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bn254PointG1.IsOnCurve())

	bG1 := NewPointG1().G1
	var scalarBigInt big.Int
	bn254Scalar.BigInt(&scalarBigInt)
	computedG1 := bG1.ScalarMultiplication(bG1, &scalarBigInt)

	require.True(t, bn254PointG1.Equal(computedG1))
}

func TestGroupG1_CreatePointForScalarZero(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	scalar.SetInt64(0)
	bn254Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bn254Scalar.IsZero())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	bn254PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)

	bG1 := NewPointG1().G1
	var scalarBigInt big.Int
	bn254Scalar.BigInt(&scalarBigInt)
	computedG1 := bG1.ScalarMultiplication(bG1, &scalarBigInt)

	require.True(t, bn254PointG1.Equal(computedG1))
}

func TestGroupG1_CreatePointForScalarOne(t *testing.T) {
	t.Parallel()

	grG1 := &groupG1{}

	scalar := grG1.CreateScalar()
	scalar.SetInt64(1)
	bn254Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bn254Scalar.IsOne())

	pG1 := grG1.CreatePointForScalar(scalar)
	require.NotNil(t, pG1)

	baseG1 := NewPointG1().G1
	bn254PointG1, ok := pG1.GetUnderlyingObj().(*gnark.G1Jac)
	require.True(t, ok)
	require.True(t, bn254PointG1.Equal(baseG1))
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
