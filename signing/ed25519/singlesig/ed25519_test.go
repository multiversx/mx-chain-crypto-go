package singlesig_test

import (
	goEd25519 "crypto/ed25519"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/mock"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
)

func TestEd25519SignerSign_NilPrivateKeyShoudErr(t *testing.T) {
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}

	_, err := signer.Sign(nil, message)
	assert.Equal(t, crypto.ErrNilPrivateKey, err)
}

func TestEd25519SignerSign_InvalidPrivateKeyTypeShoudErr(t *testing.T) {
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}

	scalar := &mock.ScalarMock{
		GetUnderlyingObjStub: func() interface{} {
			return "this is not a byte array"
		},
	}

	privateKey := &mock.PrivateKeyStub{
		ScalarStub: func() crypto.Scalar {
			return scalar
		},
	}

	_, err := signer.Sign(privateKey, message)
	assert.Equal(t, crypto.ErrInvalidPrivateKey, err)
}

func TestEd25519SignerSign_InvalidPrivateKeyLengthShoudErr(t *testing.T) {
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}

	scalar := &mock.ScalarMock{
		GetUnderlyingObjStub: func() interface{} {
			return goEd25519.PrivateKey("incorrect length")
		},
	}

	privateKey := &mock.PrivateKeyStub{
		ScalarStub: func() crypto.Scalar {
			return scalar
		},
	}

	_, err := signer.Sign(privateKey, message)
	assert.Equal(t, crypto.ErrInvalidPrivateKey, err)
}

func TestEd25519SignerSign_CorrectParamsShouldNotError(t *testing.T) {
	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	privateKey, _ := keyGenerator.GeneratePair()
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}
	_, err := signer.Sign(privateKey, message)
	assert.Nil(t, err)
}

func TestEd25519SignerVerify_NilPublicKeyShouldErr(t *testing.T) {
	signer := &singlesig.Ed25519Signer{}

	err := signer.Verify(nil, []byte(""), []byte(""))
	assert.Equal(t, crypto.ErrNilPublicKey, err)
}

func TestEd25519SignerVerify_InvalidPublicKeyTypeShouldErr(t *testing.T) {
	signer := &singlesig.Ed25519Signer{}

	publicKey := &mock.PublicKeyStub{
		PointStub: func() crypto.Point {
			return &mock.PointMock{
				GetUnderlyingObjStub: func() interface{} {
					return "this is not a byte array"
				},
			}
		},
	}

	err := signer.Verify(publicKey, []byte(""), []byte(""))
	assert.Equal(t, crypto.ErrInvalidPublicKey, err)
}

func TestEd25519SignerVerify_InvalidPublicKeyLengthShouldErr(t *testing.T) {
	signer := &singlesig.Ed25519Signer{}

	publicKey := &mock.PublicKeyStub{
		PointStub: func() crypto.Point {
			return &mock.PointMock{
				GetUnderlyingObjStub: func() interface{} {
					return goEd25519.PublicKey("incorrect length")
				},
			}
		},
	}

	err := signer.Verify(publicKey, []byte(""), []byte(""))
	assert.Equal(t, crypto.ErrInvalidPublicKey, err)
}

func TestEd25519SignerVerify_InvalidSigError(t *testing.T) {
	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	privateKey, publicKey := keyGenerator.GeneratePair()
	message := []byte("message to sign")
	alteredMessage := []byte("message to sign altered")
	signer := &singlesig.Ed25519Signer{}
	sig, _ := signer.Sign(privateKey, message)
	err := signer.Verify(publicKey, alteredMessage, sig)
	assert.Equal(t, crypto.ErrEd25519InvalidSignature, err)
}

func TestEd25519SignerVerify_InvalidSigErrorForDifferentPubKey(t *testing.T) {
	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	privateKey, _ := keyGenerator.GeneratePair()
	_, publicKey2 := keyGenerator.GeneratePair()
	message := []byte("message to sign")
	alteredMessage := []byte("message to sign altered")
	signer := &singlesig.Ed25519Signer{}
	sig, _ := signer.Sign(privateKey, message)
	err := signer.Verify(publicKey2, alteredMessage, sig)
	assert.Equal(t, crypto.ErrEd25519InvalidSignature, err)
}

func TestEd25519SignerVerify_CorrectSignature(t *testing.T) {
	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	privateKey, publicKey := keyGenerator.GeneratePair()
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}
	sig, _ := signer.Sign(privateKey, message)
	err := signer.Verify(publicKey, message, sig)
	assert.Nil(t, err)
}

func TestEd25519SignerVerify_SmallOrderPublicKeysShouldErr(t *testing.T) {
	smallOrderGeneratorBytes, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	require.NoError(t, err)

	smallOrderGenerator, err := new(edwards25519.Point).SetBytes(smallOrderGeneratorBytes)
	require.NoError(t, err)

	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	signer := &singlesig.Ed25519Signer{}
	point := edwards25519.NewIdentityPoint()

	for idx := 0; idx < 8; idx++ {
		publicKeyBytes := point.Bytes()
		cofactoredPoint := new(edwards25519.Point).MultByCofactor(point)
		require.Equal(t, 1, cofactoredPoint.Equal(edwards25519.NewIdentityPoint()))

		publicKey, keyErr := keyGenerator.PublicKeyFromByteArray(publicKeyBytes)
		require.NoError(t, keyErr)

		verifyErr := signer.Verify(publicKey, []byte("message"), make([]byte, goEd25519.SignatureSize))
		assert.Equal(t, crypto.ErrInvalidPublicKey, verifyErr, "small-order point %d", idx)

		point.Add(point, smallOrderGenerator)
	}
}

func TestEd25519SignerVerify_NonCanonicalSmallOrderPublicKeysShouldErr(t *testing.T) {
	nonCanonicalSmallOrderKeys := []string{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}

	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	signer := &singlesig.Ed25519Signer{}
	signature := make([]byte, goEd25519.SignatureSize)
	signature[0] = 1

	for _, encodedKey := range nonCanonicalSmallOrderKeys {
		publicKeyBytes, err := hex.DecodeString(encodedKey)
		require.NoError(t, err)
		point, err := new(edwards25519.Point).SetBytes(publicKeyBytes)
		require.NoError(t, err)
		cofactoredPoint := new(edwards25519.Point).MultByCofactor(point)
		require.Equal(t, 1, cofactoredPoint.Equal(edwards25519.NewIdentityPoint()))
		require.True(t, standardLibraryAcceptsSignatureForAnyMessage(publicKeyBytes, signature))

		publicKey, err := keyGenerator.PublicKeyFromByteArray(publicKeyBytes)
		require.NoError(t, err)

		err = signer.Verify(publicKey, []byte("message"), signature)
		assert.Equal(t, crypto.ErrInvalidPublicKey, err, encodedKey)
	}
}

func TestEd25519SignerVerify_SmallOrderPublicKeyForgedSignaturesShouldErr(t *testing.T) {
	publicKeyBytes, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	require.NoError(t, err)
	signature := make([]byte, goEd25519.SignatureSize)
	signature[0] = 1

	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	publicKey, err := keyGenerator.PublicKeyFromByteArray(publicKeyBytes)
	require.NoError(t, err)
	signer := &singlesig.Ed25519Signer{}
	for messageValue := 0; messageValue < 256; messageValue++ {
		message := []byte{byte(messageValue)}
		err = signer.Verify(publicKey, message, signature)
		assert.Equal(t, crypto.ErrInvalidPublicKey, err)
	}

	assert.True(t, standardLibraryAcceptsSignatureForAnyMessage(publicKeyBytes, signature))
}

func standardLibraryAcceptsSignatureForAnyMessage(publicKey []byte, signature []byte) bool {
	for messageValue := 0; messageValue < 256; messageValue++ {
		if goEd25519.Verify(publicKey, []byte{byte(messageValue)}, signature) {
			return true
		}
	}

	return false
}

func BenchmarkEd25519SignerVerify(b *testing.B) {
	suite := ed25519.NewEd25519()
	keyGenerator := signing.NewKeyGenerator(suite)
	privateKey, publicKey := keyGenerator.GeneratePair()
	message := []byte("message to sign")
	signer := &singlesig.Ed25519Signer{}
	signature, err := signer.Sign(privateKey, message)
	require.NoError(b, err)
	b.Run("legacy verifier", func(b *testing.B) {
		b.ReportAllocs()
		for idx := 0; idx < b.N; idx++ {
			if !verifyWithoutSmallOrderCheck(publicKey, message, signature) {
				b.Fatal("signature verification failed")
			}
		}
	})

	b.Run("signer", func(b *testing.B) {
		b.ReportAllocs()
		for idx := 0; idx < b.N; idx++ {
			err = signer.Verify(publicKey, message, signature)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func verifyWithoutSmallOrderCheck(publicKey crypto.PublicKey, message []byte, signature []byte) bool {
	point, ok := publicKey.Point().GetUnderlyingObj().(goEd25519.PublicKey)
	if !ok || len(point) != goEd25519.PublicKeySize {
		return false
	}

	return goEd25519.Verify(point, message, signature)
}
