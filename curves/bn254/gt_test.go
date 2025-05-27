package bn254

import (
	"testing"

	gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupGT_String(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	str := grGT.String()
	require.Equal(t, str, "BN254 GT")
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
	require.Equal(t, 32*12, x)
}

func TestGroupGT_CreatePoint(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	x := grGT.CreatePoint()
	require.NotNil(t, x)

	bn254Point, ok := x.GetUnderlyingObj().(*gnark.GT)
	require.True(t, ok)
	// points created on GT are initialized with PointZero
	require.True(t, bn254Point.IsZero())
}

func TestGroupGT_CreateScalar(t *testing.T) {
	t.Parallel()

	grGT := &groupGT{}

	sc := grGT.CreateScalar()
	require.NotNil(t, sc)

	bn254Scalar, ok := sc.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bn254Scalar.IsZero())
	require.False(t, bn254Scalar.IsOne())
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
	bn254Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	require.True(t, ok)
	require.False(t, bn254Scalar.IsZero())
	require.False(t, bn254Scalar.IsOne())

	_ = grGT.CreatePointForScalar(scalar)
}

func TestGroupGT_IsInterfaceNil(t *testing.T) {
	t.Parallel()

	var grGT *groupGT

	require.True(t, grGT.IsInterfaceNil())
	grGT = &groupGT{}
	require.False(t, grGT.IsInterfaceNil())
}
