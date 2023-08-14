package crypto

import (
	crand "crypto/rand"
	"io"
)

func randBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := crand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func CRandBytes(numBytes int) []byte {
	return randBytes(numBytes)
}

func CReader() io.Reader {
	return crand.Reader
}
