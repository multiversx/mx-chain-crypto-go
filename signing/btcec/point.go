package btcec

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

var _ crypto.Point = (*btcecPoint)(nil)

type btcecPoint struct {
	Point *btcec.PublicKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (bp *btcecPoint) GetUnderlyingObj() interface{} {
	return bp.Point
}

// MarshalBinary transforms the Point into a byte array
func (bp *btcecPoint) MarshalBinary() ([]byte, error) {
	return bp.Point.SerializeCompressed(), nil
}

// UnmarshalBinary recreates the Point from a byte array
func (bp *btcecPoint) UnmarshalBinary(key []byte) error {
	pubKey, err := btcec.ParsePubKey(key, btcec.S256())
	if err != nil {
		return err
	}

	bp.Point = pubKey

	return nil
}

// Clone returns a clone of the receiver.
func (bp *btcecPoint) Clone() crypto.Point {
	if bp == nil {
		return nil
	}

	es2 := *bp
	return &es2
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (bp *btcecPoint) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(p) {
		return false, crypto.ErrNilParam
	}

	publicKey, ok := p.GetUnderlyingObj().(*btcec.PublicKey)
	if !ok {
		return false, crypto.ErrInvalidPublicKey
	}

	return publicKey.IsEqual(bp.Point), nil
}

// Set sets the receiver equal to another Point p.
func (bp *btcecPoint) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	point, ok := p.(*btcecPoint)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	bp.Point = point.Point

	return nil
}

// Null returns nil
func (bp *btcecPoint) Null() crypto.Point {
	log.Warn("btcecPoint", "Null not implemented")

	return nil
}

// Add returns nil
func (bp *btcecPoint) Add(p crypto.Point) (crypto.Point, error) {
	log.Warn("btcecPoint", "Add not implemented")

	return nil, crypto.ErrNotImplemented
}

// Sub returns nil
func (bp *btcecPoint) Sub(p crypto.Point) (crypto.Point, error) {
	log.Warn("btcecPoint", "Sub not implemented")

	return nil, crypto.ErrNotImplemented
}

// Neg returns nil
func (bp *btcecPoint) Neg() crypto.Point {
	log.Warn("btcecPoint", "Neg not implemented")

	return nil
}

// Mul returns nil
func (bp *btcecPoint) Mul(s crypto.Scalar) (crypto.Point, error) {
	log.Warn("btcecPoint", "Mul not implemented")

	return nil, crypto.ErrNotImplemented
}

// Pick returns nil
func (bp *btcecPoint) Pick() (crypto.Point, error) {
	log.Warn("btcecPoint", "Pick not implemented")

	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (bp *btcecPoint) IsInterfaceNil() bool {
	return bp == nil
}
