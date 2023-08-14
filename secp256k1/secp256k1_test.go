package secp256k1_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/secp256k1"
)

type keyData struct {
	priv string
	pub  string
}

var keyDatas = []keyData{
	{
		priv: "d7db5e3d64c379ff3f4e0371553c19d27e79f638a61fe4b329fbfccd04b4cac6",
		pub:  "0222a49711bc49acfb44c141928f9dfa7f04128779e42b84a99a35bf514cbc308f",
	},
}

func TestPubKey(t *testing.T) {
	for _, d := range keyDatas {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)

		var priv secp256k1.PrivKey
		copy(priv[:], privB)
		pubKey := priv.PubKey()
		pubT, _ := pubKey.(secp256k1.PubKey)
		pub := pubT[:]

		assert.Equal(t, pub, pubB, "Expected pub keys to match")

		copy(pubT[:], pubB)

		assert.True(t, pubKey.Equals(pubT))

		pubT[7] ^= byte(0x01)

		assert.False(t, pubKey.Equals(pubT))
	}
}

func TestSignAndValidate(t *testing.T) {
	privKey := secp256k1.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	assert.True(t, pubKey.Verify(msg, sig))

	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.Verify(msg, sig))
}
