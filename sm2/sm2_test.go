package sm2_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/sm2"
)

type keyData struct {
	priv string
	pub  string
}

var keyDatas = []keyData{
	{
		priv: "d7db5e3d64c379ff3f4e0371553c19d27e79f638a61fe4b329fbfccd04b4cac6",
		pub:  "04f2265d4936a78d438ad6f82f940874031017f00b2d494f1d677e4dbb06b277dc5e79d3e66fea2bb1704eaf6cd6e82327108b13121c420be8852d940f6fc77049",
	},
}

func TestPubKey(t *testing.T) {
	for _, d := range keyDatas {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)

		var priv sm2.PrivKey
		copy(priv[:], privB)
		pubKey := priv.PubKey()
		pubT, _ := pubKey.(sm2.PubKey)
		pub := pubT[:]

		assert.Equal(t, pub, pubB, "Expected pub keys to match")

		copy(pubT[:], pubB)

		assert.True(t, pubKey.Equals(pubT))

		pubT[7] ^= byte(0x01)

		assert.False(t, pubKey.Equals(pubT))
	}
}

func TestSignAndValidate(t *testing.T) {
	privKey := sm2.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	assert.True(t, pubKey.Verify(msg, sig))

	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.Verify(msg, sig))
}
