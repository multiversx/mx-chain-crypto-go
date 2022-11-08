package singlesig_test

import (
	"testing"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/ElrondNetwork/elrond-go-crypto/mock"
	"github.com/ElrondNetwork/elrond-go-crypto/signing"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/btcec"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/btcec/singlesig"
	"github.com/stretchr/testify/assert"
)

func TestSigner_Sign(t *testing.T) {
	t.Parallel()

	t.Run("nil private key should error", func(t *testing.T) {
		t.Parallel()

		message := []byte("message to sign")
		signer := &singlesig.BtcecSigner{}

		_, err := signer.Sign(nil, message)
		assert.Equal(t, crypto.ErrNilPrivateKey, err)
	})

	t.Run("invalid private key type", func(t *testing.T) {
		t.Parallel()

		message := []byte("message to sign")
		signer := &singlesig.BtcecSigner{}

		scalar := &mock.ScalarMock{
			GetUnderlyingObjStub: func() interface{} {
				return "not a byte array"
			},
		}

		privateKey := &mock.PrivateKeyStub{
			ScalarStub: func() crypto.Scalar {
				return scalar
			},
		}

		_, err := signer.Sign(privateKey, message)
		assert.Equal(t, crypto.ErrInvalidPrivateKey, err)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		keyGenerator := signing.NewKeyGenerator(suite)
		privateKey, _ := keyGenerator.GeneratePair()

		message := []byte("message to sign")
		signer := &singlesig.BtcecSigner{}

		_, err := signer.Sign(privateKey, message)
		assert.Nil(t, err)
	})
}

func TestSigner_Verify(t *testing.T) {
	t.Parallel()

	t.Run("nil private key should error", func(t *testing.T) {
		t.Parallel()

		signer := &singlesig.BtcecSigner{}

		err := signer.Verify(nil, []byte(""), []byte(""))
		assert.Equal(t, crypto.ErrNilPublicKey, err)
	})

	t.Run("invalid public key type should error", func(t *testing.T) {
		t.Parallel()

		signer := &singlesig.BtcecSigner{}

		publicKey := &mock.PublicKeyStub{
			PointStub: func() crypto.Point {
				return &mock.PointMock{
					GetUnderlyingObjStub: func() interface{} {
						return "not a byte array"
					},
				}
			},
		}

		err := signer.Verify(publicKey, []byte(""), []byte(""))
		assert.Equal(t, crypto.ErrInvalidPublicKey, err)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		keyGenerator := signing.NewKeyGenerator(suite)
		privateKey, publicKey := keyGenerator.GeneratePair()

		message := []byte("message to sign")
		signer := &singlesig.BtcecSigner{}

		sig, _ := signer.Sign(privateKey, message)
		err := signer.Verify(publicKey, message, sig)
		assert.Nil(t, err)
	})
}
