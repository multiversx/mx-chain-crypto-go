package bls12381

import (
	gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupGT_String(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	str := grGT.String()
	require.Equal(t, str, "BLS12-381 GT")
}

func TestGroupGT_ScalarLen(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	x := grGT.ScalarLen()
	require.Equal(t, 32, x)
}

func TestGroupGT_PointLen(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	x := grGT.PointLen()
	require.Equal(t, 48*12, x)
}

func TestGroupGT_CreatePoint(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	x := grGT.CreatePoint()
	require.NotNil(t, x)

	bls12381Point, ok := x.GetUnderlyingObj().(*gnark.GT)
	require.True(t, ok)
	// points created on GT are initialized with PointZero
	require.True(t, bls12381Point.IsZero())
}

func TestGroupGT_CreateScalar(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	sc := grGT.CreateScalar()
	require.NotNil(t, sc)

	mclScalar, ok := sc.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, mclScalar.IsZero())
	require.False(t, mclScalar.IsOne())
}

func TestGroupGT_CreatePointForScalar(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			assert.Fail(t, "should panic as currently not supported")
		}
	}()

	grGT := &groupGT{}

	scalar := grGT.CreateScalar()
	mclScalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, mclScalar.IsZero())
	require.False(t, mclScalar.IsOne())

	_ = grGT.CreatePointForScalar(scalar)
}

func TestGroupGT_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var grGT *groupGT

	require.True(t, grGT.IsInterfaceNil())
	grGT = &groupGT{}
	require.False(t, grGT.IsInterfaceNil())
}
