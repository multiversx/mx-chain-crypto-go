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

func TestAggregateSignaturesKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSignerKOSK{}

	err := generateJSONFileKOSKForAggregateSignaturesTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "multisigKOSKAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testName := testVector.testName
		signatures := testVector.signatures
		pubKeys := testVector.publicKeys
		expectedError := testVector.expectedError
		aggregatedSig := testVector.aggregatedSig

		t.Run(testName, func(t *testing.T) {
			returnedVal, err := lls.AggregateSignatures(suite, signatures, pubKeys)
			require.Equal(t, expectedError, err)
			require.Equal(t, aggregatedSig, returnedVal)
		})
	}

}

func TestVerifyAggregatedSigKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSignerKOSK{}
	err := generateJSONFileKOSKForVerifyAggregatedSigTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "multisigKOSKVerifyAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testName := testVector.testName
		message := testVector.message
		publicKeys := testVector.publicKeys
		expectedError := testVector.expectedError
		aggregatedSig := testVector.aggregatedSig

		t.Run(testName, func(t *testing.T) {
			returnedErr := lls.VerifyAggregatedSig(suite, publicKeys, aggregatedSig, message)
			require.Equal(t, expectedError, returnedErr)

		})
	}

}

func TestAggregateSignaturesNonKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSigner{}
	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(t, err)
	lls.Hasher = hasher

	err = generateJSONFileNonKOSKForAggregateSignaturesTests(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "multisigNonKOSKAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testName := testVector.testName
		signatures := testVector.signatures
		publicKeys := testVector.publicKeys
		expectedError := testVector.expectedError
		aggregatedSig := testVector.aggregatedSig
		t.Run(testName, func(t *testing.T) {
			returnedVal, err := lls.AggregateSignatures(suite, signatures, publicKeys)
			require.Equal(t, expectedError, err)
			require.Equal(t, aggregatedSig, returnedVal)
		})
	}

}

func TestVerifyAggregatedSigNonKOSK(t *testing.T) {
	t.Parallel()

	lls := &BlsMultiSigner{}
	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(t, err)
	lls.Hasher = hasher

	err = generateJSONFileNonKOSKForVerifyAggregatedSig(lls)
	require.Nil(t, err)

	suite := mcl.NewSuiteBLS12()
	testVectors, err := createTestSetup(suite, "multisigNonKOSKVerifyAggSig.json")
	require.Nil(t, err)

	for _, testVector := range testVectors {
		testName := testVector.testName
		message := testVector.message
		publicKeys := testVector.publicKeys
		expectedError := testVector.expectedError
		aggregatedSig := testVector.aggregatedSig
		t.Run(testName, func(t *testing.T) {
			returnedErr := lls.VerifyAggregatedSig(suite, publicKeys, aggregatedSig, message)
			require.Equal(t, expectedError, returnedErr)
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
	var jsonContent JSONFileContent
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

		var pubKeys []crypto.PublicKey
		var sigs [][]byte

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
