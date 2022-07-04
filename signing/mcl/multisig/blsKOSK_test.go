package multisig_test

import (
	"testing"

	"github.com/ElrondNetwork/elrond-go-crypto/signing/mcl/multisig"
	"github.com/stretchr/testify/require"
)

func TestBlsMultiSignerKOSK_VerifySigBytes(t *testing.T) {

}

func TestBlsMultiSignerKOSK_SignShare(t *testing.T) {

}

func TestBlsMultiSignerKOSK_VerifySigShare(t *testing.T) {

}

func TestBlsMultiSignerKOSK_AggregateSignatures(t *testing.T) {

}

func TestBlsMultiSignerKOSK_VerifyAggregatedSigOK(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	llSig := &multisig.BlsMultiSignerKOSK{}
	pubKeys, sigShares := createSigSharesBLS(20, msg, llSig)
	aggSig, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(t, err)

	err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, aggSig, msg)

	require.Nil(t, err)
}
