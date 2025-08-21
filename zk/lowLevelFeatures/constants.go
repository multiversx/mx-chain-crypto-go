package lowLevelFeatures

import (
	"github.com/consensys/gnark-crypto/ecc"
)

type ID = ecc.ID

const (
	Unknown   = ecc.UNKNOWN
	BN254     = ecc.BN254
	BLS12_377 = ecc.BLS12_377
	BLS12_381 = ecc.BLS12_381
)

// GroupID defines the given group
type GroupID uint16

const (
	UnknownGroup GroupID = iota
	G1
	G2
)
