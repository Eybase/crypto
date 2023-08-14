package sm2

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

const (
	PubKeyBytesLenUncompressed = 65

	pubkeyUncompressed byte = 0x4
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func ParsePubKey(pubKeyStr []byte, curve elliptic.Curve) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])

	default:
		return nil, fmt.Errorf("invalid pub key length %d", len(pubKeyStr))
	}

	return &pubkey, nil
}

func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
