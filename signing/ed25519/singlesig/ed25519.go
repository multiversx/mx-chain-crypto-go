package singlesig

import (
	"crypto/ed25519"

	"github.com/multiversx/mx-chain-core-go/core/check"

	"github.com/multiversx/mx-chain-crypto-go"
)

// Normalizing the X sign bit reduces the 14 accepted encodings of the eight small-order points to seven entries.
var smallOrderPublicKeyEncodings = createSmallOrderPublicKeyEncodings()

// Ed25519Signer exposes the signing and verification functionalities from the ed25519 signature scheme
type Ed25519Signer struct{}

// Sign will sign a message using ed25519 signature scheme
func (e *Ed25519Signer) Sign(private crypto.PrivateKey, msg []byte) ([]byte, error) {
	if check.IfNil(private) {
		return nil, crypto.ErrNilPrivateKey
	}

	ed25519Scalar, ok := private.Scalar().GetUnderlyingObj().(ed25519.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}
	if len(ed25519Scalar) != ed25519.PrivateKeySize {
		return nil, crypto.ErrInvalidPrivateKey
	}

	sig := ed25519.Sign(ed25519Scalar, msg)

	return sig, nil
}

// Verify verifies a signature using a single signature ed25519 scheme
func (e *Ed25519Signer) Verify(public crypto.PublicKey, msg []byte, sig []byte) error {
	if check.IfNil(public) {
		return crypto.ErrNilPublicKey
	}

	ed25519Point, ok := public.Point().GetUnderlyingObj().(ed25519.PublicKey)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}
	if len(ed25519Point) != ed25519.PublicKeySize {
		return crypto.ErrInvalidPublicKey
	}
	if isSmallOrderPublicKey(ed25519Point) {
		return crypto.ErrInvalidPublicKey
	}

	isValidSig := ed25519.Verify(ed25519Point, msg, sig)
	if !isValidSig {
		return crypto.ErrEd25519InvalidSignature
	}

	return nil
}

func isSmallOrderPublicKey(publicKey ed25519.PublicKey) bool {
	var normalizedEncoding [ed25519.PublicKeySize]byte
	copy(normalizedEncoding[:], publicKey)
	normalizedEncoding[ed25519.PublicKeySize-1] &= 0x7f

	for _, encoding := range smallOrderPublicKeyEncodings {
		if normalizedEncoding == encoding {
			return true
		}
	}

	return false
}

func createSmallOrderPublicKeyEncodings() [7][ed25519.PublicKeySize]byte {
	encodings := [7][ed25519.PublicKeySize]byte{
		{},
		{0x01},
		{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
		{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	}

	for idx := 1; idx < ed25519.PublicKeySize-1; idx++ {
		encodings[4][idx] = 0xff
		encodings[5][idx] = 0xff
		encodings[6][idx] = 0xff
	}
	encodings[4][0], encodings[4][ed25519.PublicKeySize-1] = 0xec, 0x7f
	encodings[5][0], encodings[5][ed25519.PublicKeySize-1] = 0xed, 0x7f
	encodings[6][0], encodings[6][ed25519.PublicKeySize-1] = 0xee, 0x7f

	return encodings
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *Ed25519Signer) IsInterfaceNil() bool {
	return e == nil
}
