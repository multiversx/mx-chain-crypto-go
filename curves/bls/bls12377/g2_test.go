package bls12377

import (
	"math/big"
	"testing"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/stretchr/testify/require"
)

func TestGroupG2_String(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	str := grG2.String()
	require.Equal(t, str, "BLS12-377 G2")
}

func TestGroupG2_ScalarLen(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	x := grG2.ScalarLen()
	require.Equal(t, 32, x)
}

func TestGroupG2_PointLen(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	x := grG2.PointLen()
	require.Equal(t, 96, x)
}

func TestGroupG2_CreatePoint(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}
	point := &PointG2{
		G2: &gnark.G2Jac{},
	}

	_, g2Gen, _, _ := gnark.Generators()
	point.G2 = &g2Gen
	x := grG2.CreatePoint()
	require.NotNil(t, x)
	bls12381Point, ok := x.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.Equal(t, point.G2, bls12381Point)
}

func TestGroupG2_CreateScalar(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	sc := grG2.CreateScalar()
	require.NotNil(t, sc)

	bls12381Scalar, ok := sc.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bls12381Scalar.IsZero())
	require.False(t, bls12381Scalar.IsOne())
}

func TestGroupG2_CreatePointForScalar(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	scalar := grG2.CreateScalar()
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bls12381Scalar.IsZero())
	require.False(t, bls12381Scalar.IsOne())

	pG2 := grG2.CreatePointForScalar(scalar)
	require.NotNil(t, pG2)

	bls12381PointG2, ok := pG2.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)

	bG2 := NewPointG2().G2
	var scalarBigInt big.Int
	bls12381Scalar.BigInt(&scalarBigInt)
	computedG2 := bG2.ScalarMultiplication(bG2, &scalarBigInt)

	require.True(t, bls12381PointG2.Equal(computedG2))
}

func TestGroupG2_CreatePointForScalarZero(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	scalar := grG2.CreateScalar()
	scalar.SetInt64(0)
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bls12381Scalar.IsZero())

	pG2 := grG2.CreatePointForScalar(scalar)
	require.NotNil(t, pG2)

	bls12381PointG2, ok := pG2.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.True(t, bls12381PointG2.Z.IsZero())

	bG2 := NewPointG2().G2
	var scalarBigInt big.Int
	bls12381Scalar.BigInt(&scalarBigInt)
	computedG2 := bG2.ScalarMultiplication(bG2, &scalarBigInt)

	require.True(t, bls12381PointG2.Equal(computedG2))
}

func TestGroupG2_CreatePointForScalarOne(t *testing.T) {
	t.Parallel()

	grG2 := &groupG2{}

	scalar := grG2.CreateScalar()
	scalar.SetInt64(1)
	bls12381Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.True(t, bls12381Scalar.IsOne())

	pG2 := grG2.CreatePointForScalar(scalar)
	require.NotNil(t, pG2)

	bG2 := NewPointG2().G2
	bls12381PointG2, ok := pG2.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.True(t, bls12381PointG2.Equal(bG2))
}

func TestGroupG2_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var grG2 *groupG2

	require.True(t, check.IfNil(grG2))
	grG2 = &groupG2{}
	require.False(t, check.IfNil(grG2))
}
