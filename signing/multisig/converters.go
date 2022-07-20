package multisig

import (
	"github.com/ElrondNetwork/elrond-go-crypto"
)

func convertBytesToPubKeys(pubKeys [][]byte, kg crypto.KeyGenerator) ([]crypto.PublicKey, error) {
	pk := make([]crypto.PublicKey, 0, len(pubKeys))
	for _, pubKeyStr := range pubKeys {
		pubKey, err := convertBytesToPubKey(pubKeyStr, kg)
		if err != nil {
			return nil, err
		}

		pk = append(pk, pubKey)
	}
	return pk, nil
}

func convertBytesToPubKey(pubKeyBytes []byte, kg crypto.KeyGenerator) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 {
		return nil, crypto.ErrEmptyPubKeyString
	}

	return kg.PublicKeyFromByteArray(pubKeyBytes)
}

func convertBytesToPrivateKey(privateKey []byte, kg crypto.KeyGenerator) (crypto.PrivateKey, error) {
	if len(privateKey) == 0 {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return kg.PrivateKeyFromByteArray(privateKey)
}
