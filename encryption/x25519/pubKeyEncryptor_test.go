package x25519_test

import (
	"encoding/hex"
	"errors"
	"github.com/ElrondNetwork/elrond-go-core/core"
	"github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/ElrondNetwork/elrond-go-crypto/encryption/x25519"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/ed25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptedData_EncryptDecryptProcessOK(t *testing.T) {
	data := []byte("encrypt me")
	edSuite := ed25519.NewEd25519()
	keyGenerator := crypto.NewKeyGenerator(edSuite)
	encryptedData := x25519.EncryptedData{}
	receiverSecret, receiverPub := keyGenerator.GeneratePair()
	senderSecret, _ := keyGenerator.GeneratePair()

	_ = encryptedData.Encrypt(data, receiverPub, senderSecret)
	decryptedData, err := encryptedData.Decrypt(receiverSecret)

	require.Nil(t, err)
	require.Equal(t, data, decryptedData)
}

func TestEncryptedData_ErdJSEncryptedDataForBob(t *testing.T) {
	encryptedMessage := []byte("alice's secret text for bob")
	bobSecret, _ := hex.DecodeString("b8ca6f8203fb4b545a8e83c5384da033c415db155b53fb5b8eba7ff5a039d639")
	edSuite := ed25519.NewEd25519()
	keyGenerator := crypto.NewKeyGenerator(edSuite)
	bobPrivate, _ := keyGenerator.PrivateKeyFromByteArray(bobSecret)

	encryptedData := x25519.EncryptedData{}
	_ = core.LoadJsonFile(&encryptedData, "testdata/encryptedData.json")

	decryptedData, err := encryptedData.Decrypt(bobPrivate)

	require.Nil(t, err)
	require.Equal(t, encryptedMessage, decryptedData)
}

func TestEncryptedData_DecryptWithWrongSecret(t *testing.T) {
	bobInvalidSecret, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	edSuite := ed25519.NewEd25519()
	keyGenerator := crypto.NewKeyGenerator(edSuite)
	bobInvalidPrivate, _ := keyGenerator.PrivateKeyFromByteArray(bobInvalidSecret)

	encryptedData := x25519.EncryptedData{}
	_ = core.LoadJsonFile(&encryptedData, "testdata/encryptedData.json")

	decryptedData, err := encryptedData.Decrypt(bobInvalidPrivate)
	require.Equal(t, crypto.ErrFailedAuthentication, err)
	require.Nil(t, decryptedData)
}

func TestEncryptedData_DecryptWithWrongOriginator(t *testing.T) {
	invalidAuthSignature := errors.New("ed25519: invalid signature")
	bobSecret, _ := hex.DecodeString("b8ca6f8203fb4b545a8e83c5384da033c415db155b53fb5b8eba7ff5a039d639")
	invalidOriginator := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	edSuite := ed25519.NewEd25519()
	keyGenerator := crypto.NewKeyGenerator(edSuite)
	bobPrivate, _ := keyGenerator.PrivateKeyFromByteArray(bobSecret)

	encryptedData := x25519.EncryptedData{}
	_ = core.LoadJsonFile(&encryptedData, "testdata/encryptedData.json")
	encryptedData.Identities.OriginatorPubKey = invalidOriginator

	decryptedData, err := encryptedData.Decrypt(bobPrivate)

	require.Equal(t, invalidAuthSignature, err)
	require.Nil(t, decryptedData)
}

func TestEncryptedData_DecryptWithWrongEphemeral(t *testing.T) {
	invalidAuthSignature := errors.New("ed25519: invalid signature")
	bobSecret, _ := hex.DecodeString("b8ca6f8203fb4b545a8e83c5384da033c415db155b53fb5b8eba7ff5a039d639")
	invalidEphemeral := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	edSuite := ed25519.NewEd25519()
	keyGenerator := crypto.NewKeyGenerator(edSuite)
	bobPrivate, _ := keyGenerator.PrivateKeyFromByteArray(bobSecret)

	encryptedData := x25519.EncryptedData{}
	_ = core.LoadJsonFile(&encryptedData, "testdata/encryptedData.json")
	encryptedData.Identities.EphemeralPubKey = invalidEphemeral

	decryptedData, err := encryptedData.Decrypt(bobPrivate)

	require.Equal(t, invalidAuthSignature, err)
	require.Nil(t, decryptedData)
}
