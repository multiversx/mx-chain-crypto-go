package multisig

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
)

// TestVector defines the data structure used to unmarshal the JSON file
type TestVector struct {
	testName      string
	message       []byte
	publicKeys    []crypto.PublicKey
	signatures    [][]byte
	aggregatedSig []byte
	expectedError error
}

func TestAggregateSignatures(t *testing.T) {
	t.Parallel()
	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite)
	require.Nil(t, err)

	lls := &BlsMultiSignerKOSK{}

	for i := range testVectors {
		t.Run(testVectors[i].testName, func(t *testing.T) {
			t.Parallel()

			returnedVal, err := lls.AggregateSignatures(suite, testVectors[i].signatures, testVectors[i].publicKeys)
			require.Equal(t, testVectors[i].expectedError, err)
			require.Equal(t, testVectors[i].aggregatedSig, returnedVal)
		})
	}

}

func TestVerifyAggregatedSig(t *testing.T) {
	t.Parallel()
	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite)
	require.Nil(t, err)

	lls := &BlsMultiSignerKOSK{}

	for i := range testVectors {
		t.Run(testVectors[i].testName, func(t *testing.T) {
			t.Parallel()

			returnedErr := lls.VerifyAggregatedSig(suite, testVectors[i].publicKeys, testVectors[i].aggregatedSig, testVectors[i].message)
			require.Equal(t, testVectors[i].expectedError, returnedErr)

		})
	}

}

func createTestSetup(suite crypto.Suite) ([]TestVector, error) {
	var testVectors []TestVector
	kg := signing.NewKeyGenerator(suite)

	content, err := os.ReadFile("KOSKmultisig.json")
	if err != nil {
		return nil, err
	}
	var jsonContent JSONFileContent
	err = json.Unmarshal(content, &jsonContent)
	if err != nil {
		return nil, err
	}

	for i := range jsonContent.TestVectors {

		testName := jsonContent.TestVectors[i].TestName
		signatures := jsonContent.TestVectors[i].Signatures
		aggregatedSig := jsonContent.TestVectors[i].AggregatedSignature
		message := jsonContent.TestVectors[i].Message
		expectedError := errors.New(jsonContent.TestVectors[i].ErrorMessage)
		if jsonContent.TestVectors[i].ErrorMessage == "noError" {
			expectedError = nil
		}

		var pubKeys []crypto.PublicKey
		var sigs [][]byte

		for j := range signatures {
			decodedValue, _ := hex.DecodeString(signatures[j].PublicKey)
			pk, _ := kg.PublicKeyFromByteArray(decodedValue)
			pubKeys = append(pubKeys, pk)
			decodedValue, _ = hex.DecodeString(signatures[j].Signature)
			sigs = append(sigs, decodedValue)
		}

		decodedAggregatedSig, _ := hex.DecodeString(aggregatedSig)
		decodedMessage, _ := hex.DecodeString(message)

		testVectors = append(testVectors, TestVector{
			testName:      testName,
			message:       decodedMessage,
			publicKeys:    pubKeys,
			signatures:    sigs,
			aggregatedSig: decodedAggregatedSig,
			expectedError: expectedError,
		})

	}
	return testVectors, nil

}
