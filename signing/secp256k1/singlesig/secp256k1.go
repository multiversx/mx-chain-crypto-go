package singlesig

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	libp2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
)

// Secp256k1Signer exposes the signing and verification for secp256k1 signature scheme
type Secp256k1Signer struct {
}

// Sign is used to sign a message
func (s *Secp256k1Signer) Sign(private crypto.PrivateKey, msg []byte) ([]byte, error) {
	if check.IfNil(private) {
		return nil, crypto.ErrNilPrivateKey
	}

	secp256k1Scalar, ok := private.Scalar().GetUnderlyingObj().(libp2pCrypto.PrivKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	sig, err := secp256k1Scalar.Sign(msg)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Verify is used to verify a signed message
func (s *Secp256k1Signer) Verify(public crypto.PublicKey, msg []byte, sig []byte) error {
	if check.IfNil(public) {
		return crypto.ErrNilPublicKey
	}

	secp256k1Point, ok := public.Point().GetUnderlyingObj().(libp2pCrypto.PubKey)
	if !ok {
		return crypto.ErrInvalidPrivateKey
	}

	sigOk, err := secp256k1Point.Verify(msg, sig)
	if err != nil {
		return err
	}
	if !sigOk {
		return crypto.ErrSigNotValid
	}

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *Secp256k1Signer) IsInterfaceNil() bool {
	return s == nil
}
