package ed25519_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/ed25519"
)

type keyData struct {
	priv string
	pub  string
}

var keyDatas = []keyData{
	{
		priv: "3245a603288a088229c0f5f7663504a14fde16883abee332a3ca7bc5e0d18a8ebd63dccc7a33b088264dcb75cc4a5cfc625a478c6b6eb1205e810493b4b6ff57",
		pub:  "bd63dccc7a33b088264dcb75cc4a5cfc625a478c6b6eb1205e810493b4b6ff57",
	},
}

func TestPubKey(t *testing.T) {
	for _, d := range keyDatas {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)

		var priv ed25519.PrivKey
		copy(priv[:], privB)
		pubKey := priv.PubKey()
		pubT, _ := pubKey.(ed25519.PubKey)
		pub := pubT[:]

		assert.Equal(t, pub, pubB, "Expected pub keys to match")

		copy(pubT[:], pubB)

		assert.True(t, pubKey.Equals(pubT))

		pubT[7] ^= byte(0x01)

		assert.False(t, pubKey.Equals(pubT))
	}
}

func TestSignAndValidate(t *testing.T) {
	privKey := ed25519.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	assert.True(t, pubKey.Verify(msg, sig))

	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.Verify(msg, sig))
}
