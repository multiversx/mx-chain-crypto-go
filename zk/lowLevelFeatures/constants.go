package lowLevelFeatures

import (
	"github.com/consensys/gnark-crypto/ecc"
)

type ID = ecc.ID

const (
	Unknown    = ecc.UNKNOWN
	BN254      = ecc.BN254
	BLS12_377  = ecc.BLS12_377
	BLS12_381  = ecc.BLS12_381
	BLS24_315  = ecc.BLS24_315
	BLS24_317  = ecc.BLS24_317
	BW6_761    = ecc.BW6_761
	BW6_633    = ecc.BW6_633
	StarkCurve = ecc.STARK_CURVE
	Secp256k1  = ecc.SECP256K1
	Grumpkin   = ecc.GRUMPKIN
)

type GroupID uint16

const (
	UnknownGroup GroupID = iota
	G1
	G2
)
