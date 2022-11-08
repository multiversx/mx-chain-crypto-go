package singlesig

import (
	"crypto/sha256"

	"github.com/ElrondNetwork/elrond-go-core/core/check"
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/btcsuite/btcd/btcec"
)

// BtcecSigner exposes the signing and verification for btcec signature scheme
type BtcecSigner struct {
}

// Sign is used to sign a message
func (s *BtcecSigner) Sign(private crypto.PrivateKey, msg []byte) ([]byte, error) {
	if check.IfNil(private) {
		return nil, crypto.ErrNilPrivateKey
	}

	privKey, ok := private.Scalar().GetUnderlyingObj().(*btcec.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	hash := sha256.Sum256(msg)
	sig, err := privKey.Sign(hash[:])
	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

// Verify is used to verify a signed message
func (s *BtcecSigner) Verify(public crypto.PublicKey, msg []byte, sig []byte) error {
	if check.IfNil(public) {
		return crypto.ErrNilPublicKey
	}

	pubKey, ok := public.Point().GetUnderlyingObj().(*btcec.PublicKey)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	signature, err := btcec.ParseDERSignature(sig, btcec.S256())
	if err != nil {
		return err
	}

	hash := sha256.Sum256(msg)
	sigOk := signature.Verify(hash[:], pubKey)
	if !sigOk {
		return crypto.ErrSigNotValid
	}

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *BtcecSigner) IsInterfaceNil() bool {
	return s == nil
}
