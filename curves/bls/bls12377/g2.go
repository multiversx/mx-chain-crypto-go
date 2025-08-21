package bls12377

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

type groupG2 struct {
}

// String returns the string for the group
func (g2 *groupG2) String() string {
	return "BLS12-377 G2"
}

// ScalarLen returns the maximum length of scalars in bytes
func (g2 *groupG2) ScalarLen() int {
	return fr.Bytes
}

// CreateScalar creates a new Scalar initialized with base point on G2
func (g2 *groupG2) CreateScalar() crypto.Scalar {
	return NewScalar()
}

// PointLen returns the max length of point in nb of bytes
func (g2 *groupG2) PointLen() int {
	return fp.Bytes * 2
}

// CreatePoint creates a new point
func (g2 *groupG2) CreatePoint() crypto.Point {
	return NewPointG2()
}

// CreatePointForScalar creates a new point corresponding to the given scalarInt
func (g2 *groupG2) CreatePointForScalar(scalar crypto.Scalar) crypto.Point {
	var p crypto.Point
	var err error
	p = NewPointG2()
	p, err = p.Mul(scalar)
	if err != nil {
		log.Error("groupG2 CreatePointForScalar", "error", err.Error())
	}
	return p
}

// IsInterfaceNil returns true if there is no value under the interface
func (g2 *groupG2) IsInterfaceNil() bool {
	return g2 == nil
}
