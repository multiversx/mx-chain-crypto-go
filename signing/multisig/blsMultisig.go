package multisig

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	"github.com/ElrondNetwork/elrond-go-crypto"
)

var _ crypto.MultiSigner = (*blsMultiSigner)(nil)

type blsMultiSigner struct {
	keyGen   crypto.KeyGenerator
	llSigner crypto.LowLevelSignerBLS
}

// NewBLSMultisig creates a new BLS multi-signer
func NewBLSMultisig(
	llSigner crypto.LowLevelSignerBLS,
	keyGen crypto.KeyGenerator,
) (*blsMultiSigner, error) {
	if check.IfNil(llSigner) {
		return nil, crypto.ErrNilLowLevelSigner
	}
	if check.IfNil(keyGen) {
		return nil, crypto.ErrNilKeyGenerator
	}
	return &blsMultiSigner{
		keyGen:   keyGen,
		llSigner: llSigner,
	}, nil
}

// CreateSignatureShare returns a BLS single signature over the message
func (bms *blsMultiSigner) CreateSignatureShare(privateKeyBytes []byte, message []byte) ([]byte, error) {
	privateKey, err := convertBytesToPrivateKey(privateKeyBytes, bms.keyGen)
	if err != nil {
		return nil, err
	}

	sigShareBytes, err := bms.llSigner.SignShare(privateKey, message)
	if err != nil {
		return nil, err
	}

	return sigShareBytes, nil
}

// VerifySignatureShare verifies the single signature share of the signer with specified position
// Signature is verified over a message configured with a previous call of SetMessage
func (bms *blsMultiSigner) VerifySignatureShare(publicKey []byte, message []byte, sig []byte) error {
	if sig == nil {
		return crypto.ErrNilSignature
	}

	pubKey, err := convertBytesToPubKey(publicKey, bms.keyGen)
	if err != nil {
		return err
	}

	return bms.llSigner.VerifySigShare(pubKey, message, sig)
}

// AggregateSigs aggregates all collected partial signatures
func (bms *blsMultiSigner) AggregateSigs(pubKeysSigners [][]byte, signatures [][]byte) ([]byte, error) {
	pubKeys, err := convertBytesToPubKeys(pubKeysSigners, bms.keyGen)
	if err != nil {
		return nil, err
	}

	return bms.llSigner.AggregateSignatures(bms.keyGen.Suite(), signatures, pubKeys)
}

// VerifyAggregatedSig verifies the aggregated signature by checking that aggregated signature is valid with respect
// to aggregated public keys.
func (bms *blsMultiSigner) VerifyAggregatedSig(pubKeysSigners [][]byte, message []byte, aggSig []byte) error {
	pubKeys, err := convertBytesToPubKeys(pubKeysSigners, bms.keyGen)
	if err != nil {
		return err
	}

	return bms.llSigner.VerifyAggregatedSig(bms.keyGen.Suite(), pubKeys, aggSig, message)
}

// IsInterfaceNil returns true if there is no value under the interface
func (bms *blsMultiSigner) IsInterfaceNil() bool {
	return bms == nil
}
