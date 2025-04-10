package ethsig

import (
	ethCommon "github.com/ethereum/go-ethereum/common"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// Signer exposes the signing and verification logic
type Signer struct {
}

// Sign returns error
func (s *Signer) Sign(crypto.PrivateKey, []byte) ([]byte, error) {
	return nil, crypto.ErrNotImplemented
}

// Verify is used to verify a signed message
func (s *Signer) Verify(publicKey crypto.PublicKey, msg []byte, sig []byte) error {
	if check.IfNil(publicKey) {
		return crypto.ErrNilPublicKey
	}

	address, err := publicKey.ToByteArray()
	if err != nil {
		return crypto.ErrInvalidPublicKey
	}

	recoveredPublicKey, err := ethCrypto.SigToPub(msg, sig)
	if err != nil {
		return err
	}

	recoveredAddress := ethCrypto.PubkeyToAddress(*recoveredPublicKey)
	if recoveredAddress != ethCommon.BytesToAddress(address) {
		return crypto.ErrSigNotValid
	}

	return nil
}

func (s *Signer) IsInterfaceNil() bool {
	return s == nil
}
