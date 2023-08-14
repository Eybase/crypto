package secp256k1_test

import (
	"testing"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/internal/benchmark"
	"github.com/eybase/crypto/secp256k1"
)

func BenchmarkGenPrivKey(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return secp256k1.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKey(b, wrapperGenPrivKey)
}

func BenchmarkGenPrivKeyParallel(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return secp256k1.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKeyParallel(b, wrapperGenPrivKey)
}

func BenchmarkSign(b *testing.B) {
	priv := secp256k1.GenPrivKey()
	benchmark.BenchmarkSign(b, priv)
}

func BenchmarkSignParallel(b *testing.B) {
	priv := secp256k1.GenPrivKey()
	benchmark.BenchmarkSignParallel(b, priv)
}

func BenchmarkVerify(b *testing.B) {
	priv := secp256k1.GenPrivKey()
	benchmark.BenchmarkVerify(b, priv)
}

func BenchmarkVerifyParallel(b *testing.B) {
	priv := secp256k1.GenPrivKey()
	benchmark.BenchmarkVerifyParallel(b, priv)
}
