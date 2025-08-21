package bls12377

import (
	"testing"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/mock"
	"github.com/stretchr/testify/require"
)

func TestBLSScalar_EqualInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().Zero()
	scalar2 := &mock.ScalarMock{}
	eq, err := scalar1.Equal(scalar2)

	require.False(t, eq)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestBLSScalar_EqualTrue(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar().One()
	eq, err := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_EqualFalse(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar().Zero()
	eq, err := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.False(t, eq)
}

func TestBLSScalar_SetNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar := NewScalar().One()
	err := scalar.Set(nil)

	require.Equal(t, crypto.ErrNilParam, err)
}

func TestBLSScalar_SetInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := &mock.ScalarMock{}
	err := scalar1.Set(scalar2)

	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestBLSScalar_SetOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar().Zero()
	err := scalar1.Set(scalar2)
	eq, _ := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_Clone(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := scalar1.Clone()
	eq, err := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_SetInt64(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar2 := NewScalar()
	scalar1.SetInt64(int64(555555555))
	scalar2.SetInt64(int64(444444444))

	diff, _ := scalar1.Sub(scalar2)
	scalar3 := NewScalar()
	scalar3.SetInt64(int64(111111111))

	eq, err := diff.Equal(scalar3)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_Zero(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().Zero()
	scalar2 := NewScalar()
	scalar2.SetInt64(0)

	eq, err := scalar2.Equal(scalar1)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_AddNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar := NewScalar().Zero()
	sum, err := scalar.Add(nil)

	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, sum)
}

func TestBLSScalar_AddInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().Zero()
	scalar2 := &mock.ScalarMock{}
	sum, err := scalar1.Add(scalar2)

	require.Equal(t, crypto.ErrInvalidParam, err)
	require.Nil(t, sum)
}

func TestBLSScalar_AddOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar().One()
	sum, err := scalar1.Add(scalar2)
	require.Nil(t, err)
	scalar3 := NewScalar()
	scalar3.SetInt64(2)
	eq, err := scalar3.Equal(sum)

	require.True(t, eq)
	require.Nil(t, err)
}

func TestBLSScalar_SubNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar := NewScalar().Zero()
	diff, err := scalar.Sub(nil)

	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, diff)
}

func TestBLSScalar_SubInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().Zero()
	scalar2 := &mock.ScalarMock{}
	diff, err := scalar1.Sub(scalar2)

	require.Equal(t, crypto.ErrInvalidParam, err)
	require.Nil(t, diff)
}

func TestBLSScalar_SubOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar1.SetInt64(4)
	scalar2 := NewScalar().One()
	diff, err := scalar1.Sub(scalar2)
	require.Nil(t, err)
	scalar3 := NewScalar()
	scalar3.SetInt64(3)
	eq, err := scalar3.Equal(diff)

	require.True(t, eq)
	require.Nil(t, err)
}

func TestBLSScalar_Neg(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar1.SetInt64(4)
	scalar2 := scalar1.Neg()
	scalar3 := NewScalar()
	scalar3.SetInt64(-4)
	eq, err := scalar2.Equal(scalar3)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_One(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar1.SetInt64(1)
	scalar2 := NewScalar().One()

	eq, err := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.True(t, eq)
}

func TestBLSScalar_MulNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar := NewScalar().One()
	res, err := scalar.Mul(nil)

	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, res)
}

func TestBLSScalar_MulInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := &mock.ScalarMock{}
	res, err := scalar1.Mul(scalar2)

	require.Equal(t, crypto.ErrInvalidParam, err)
	require.Nil(t, res)
}

func TestBLSScalar_MulOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar()
	scalar2.SetInt64(4)
	res, err := scalar1.Mul(scalar2)

	require.Nil(t, err)

	eq, _ := res.Equal(scalar2)

	require.True(t, eq)
}

func TestBLSScalar_DivNilParamShouldEr(t *testing.T) {
	t.Parallel()

	scalar := NewScalar().One()
	res, err := scalar.Div(nil)

	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, res)
}

func TestBLSScalar_DivInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := &mock.ScalarMock{}
	res, err := scalar1.Div(scalar2)

	require.Equal(t, crypto.ErrInvalidParam, err)
	require.Nil(t, res)
}

func TestBLSScalar_DivOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	scalar2 := NewScalar()
	scalar2.SetInt64(4)
	res, err := scalar2.Div(scalar1)

	require.Nil(t, err)

	eq, _ := res.Equal(scalar2)

	require.True(t, eq)
}

func TestBLSScalar_InvNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar2, err := scalar1.Inv(nil)

	require.Nil(t, scalar2)
	require.Equal(t, crypto.ErrNilParam, err)
}

func TestBLSScalar_InvInvalidParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar2 := &mock.ScalarMock{}
	scalar3, err := scalar1.Inv(scalar2)

	require.Nil(t, scalar3)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestBLSScalar_InvOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar1.SetInt64(4)
	scalar2, err := scalar1.Inv(scalar1)
	eq, _ := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.NotNil(t, scalar2)
	require.False(t, eq)

	one := NewScalar().One()
	scalar3, err := scalar1.Inv(one)
	require.Nil(t, err)
	eq, _ = one.Equal(scalar3)

	require.True(t, eq)
}

func TestBLSScalar_PickOK(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar2, err := scalar1.Pick()
	require.Nil(t, err)
	require.NotNil(t, scalar1, scalar2)

	eq, _ := scalar1.Equal(scalar2)

	require.False(t, eq)
}

func TestBLSScalar_SetBytesNilParamShouldErr(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar()
	scalar2, err := scalar1.SetBytes(nil)

	require.Nil(t, scalar2)
	require.Equal(t, crypto.ErrNilParam, err)
}

func TestBLSScalar_SetBytesOK(t *testing.T) {
	t.Parallel()

	val := int64(555555555)
	scalar1 := NewScalar().One()

	sc2 := NewScalar()
	sc2.SetInt64(val)
	buf, _ := sc2.MarshalBinary()

	scalar2, err := scalar1.SetBytes(buf)
	require.Nil(t, err)
	require.NotEqual(t, scalar1, scalar2)

	scalar3 := NewScalar()
	scalar3.SetInt64(val)

	eq, _ := scalar3.Equal(scalar2)
	require.True(t, eq)
}

func TestBLSScalar_GetUnderlyingObj(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()
	x := scalar1.GetUnderlyingObj()

	require.NotNil(t, x)
}

func TestBLSScalar_MarshalBinary(t *testing.T) {
	t.Parallel()

	scalar1 := NewScalar().One()

	scalarBytes, err := scalar1.MarshalBinary()

	require.Nil(t, err)
	require.NotNil(t, scalarBytes)
}

func TestBLSScalar_UnmarshalBinary(t *testing.T) {
	scalar1, _ := NewScalar().Pick()
	scalarBytes, err := scalar1.MarshalBinary()
	require.Nil(t, err)
	scalar2 := NewScalar().Zero()
	err = scalar2.UnmarshalBinary(scalarBytes)
	require.Nil(t, err)

	eq, err := scalar1.Equal(scalar2)

	require.Nil(t, err)
	require.True(t, eq)
}
