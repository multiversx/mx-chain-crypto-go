package multisig

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/stretchr/testify/require"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
	testData2 "github.com/multiversx/mx-chain-crypto-go/signing/mcl/multisig/testData"
)

const blsHashSize = 16

// TestVector defines the data structure used to unmarshal the JSON file
type TestVector struct {
	testName      string
	message       []byte
	publicKeys    []crypto.PublicKey
	signatures    [][]byte
	aggregatedSig []byte
	expectedError error
}

func TestAggregateSignaturesKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSignerKOSK{}

	err := testData2.GenerateJSONFileKOSKForAggregateSignaturesTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "testData/multisigKOSKAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testVectorCopy := testVector

		t.Run(testVectorCopy.testName, func(t *testing.T) {
			returnedVal, err := lls.AggregateSignatures(suite, testVectorCopy.signatures, testVectorCopy.publicKeys)
			require.Equal(t, testVectorCopy.expectedError, err)
			require.Equal(t, testVectorCopy.aggregatedSig, returnedVal)
		})
	}

}

func TestVerifyAggregatedSigKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSignerKOSK{}
	err := testData2.GenerateJSONFileKOSKForVerifyAggregatedSigTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "testData/multisigKOSKVerifyAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testVectorCopy := testVector

		t.Run(testVectorCopy.testName, func(t *testing.T) {
			returnedErr := lls.VerifyAggregatedSig(suite, testVectorCopy.publicKeys, testVectorCopy.aggregatedSig, testVectorCopy.message)
			require.Equal(t, testVectorCopy.expectedError, returnedErr)

		})
	}

}

func TestAggregateSignaturesNonKOSK(t *testing.T) {
	t.Parallel()

	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	lls := &BlsMultiSigner{
		Hasher: hasher,
	}
	require.Nil(t, err)

	err = testData2.GenerateJSONFileNonKOSKForAggregateSignaturesTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "testData/multisigNonKOSKAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testVectorCopy := testVector

		t.Run(testVectorCopy.testName, func(t *testing.T) {
			returnedVal, err := lls.AggregateSignatures(suite, testVectorCopy.signatures, testVectorCopy.publicKeys)
			require.Equal(t, testVectorCopy.expectedError, err)
			require.Equal(t, testVectorCopy.aggregatedSig, returnedVal)
		})
	}

}

func TestVerifyAggregatedSigNonKOSK(t *testing.T) {
	t.Parallel()

	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(t, err)
	lls := &BlsMultiSigner{
		Hasher: hasher,
	}

	err = testData2.GenerateJSONFileNonKOSKForVerifyAggregatedSigTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "testData/multisigNonKOSKVerifyAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testVectorCopy := testVector

		t.Run(testVectorCopy.testName, func(t *testing.T) {
			returnedErr := lls.VerifyAggregatedSig(suite, testVectorCopy.publicKeys, testVectorCopy.aggregatedSig, testVectorCopy.message)
			require.Equal(t, testVectorCopy.expectedError, returnedErr)
		})
	}

}

func createTestSetup(suite crypto.Suite, filename string) ([]TestVector, error) {
	var testVectors []TestVector
	kg := signing.NewKeyGenerator(suite)

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var jsonContent testData2.JSONFileContent
	err = json.Unmarshal(content, &jsonContent)
	if err != nil {
		return nil, err
	}

	for _, testVector := range jsonContent.TestVectors {

		testName := testVector.TestName
		signatures := testVector.Signatures
		aggregatedSig := testVector.AggregatedSignature

		message := testVector.Message
		expectedError := errors.New(testVector.ErrorMessage)
		if testVector.ErrorMessage == "noError" {
			expectedError = nil
		}

		pubKeys := make([]crypto.PublicKey, 0, len(signatures))
		sigs := make([][]byte, 0, len(signatures))
		for _, signature := range signatures {
			decodedValue, _ := hex.DecodeString(signature.PublicKey)
			pk, _ := kg.PublicKeyFromByteArray(decodedValue)
			pubKeys = append(pubKeys, pk)

			decodedValue, _ = hex.DecodeString(signature.Signature)
			sigs = append(sigs, decodedValue)
		}

		var decodedAggregatedSig []byte
		if len(aggregatedSig) > 0 {
			decodedAggregatedSig, _ = hex.DecodeString(aggregatedSig)
		}

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
