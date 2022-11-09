package singlesig

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

// Secp256k1Signer exposes the signing and verification for ecdsa signature scheme
type Secp256k1Signer struct {
}

// Sign is used to sign a message
func (s *Secp256k1Signer) Sign(private crypto.PrivateKey, msg []byte) ([]byte, error) {
	if check.IfNil(private) {
		return nil, crypto.ErrNilPrivateKey
	}

	privKey, ok := private.Scalar().GetUnderlyingObj().(btcec.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	sig, err := privKey.Sign(msg)
	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

// Verify is used to verify a signed message
func (s *Secp256k1Signer) Verify(public crypto.PublicKey, msg []byte, sig []byte) error {
	if check.IfNil(public) {
		return crypto.ErrNilPublicKey
	}

	pubKey, ok := public.Point().GetUnderlyingObj().(btcec.PublicKey)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	signature, err := btcec.ParseDERSignature(sig, btcec.S256())
	if err != nil {
		return err
	}

	sigOk := signature.Verify(msg, &pubKey)
	if !sigOk {
		return crypto.ErrSigNotValid
	}

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *Secp256k1Signer) IsInterfaceNil() bool {
	return s == nil
}