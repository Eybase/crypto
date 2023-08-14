package sm2_test

import (
	"testing"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/internal/benchmark"
	"github.com/eybase/crypto/sm2"
)

func BenchmarkGenPrivKey(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return sm2.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKey(b, wrapperGenPrivKey)
}

func BenchmarkGenPrivKeyParallel(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return sm2.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKeyParallel(b, wrapperGenPrivKey)
}

func BenchmarkSign(b *testing.B) {
	priv := sm2.GenPrivKey()
	benchmark.BenchmarkSign(b, priv)
}

func BenchmarkSignParallel(b *testing.B) {
	priv := sm2.GenPrivKey()
	benchmark.BenchmarkSignParallel(b, priv)
}

func BenchmarkVerify(b *testing.B) {
	priv := sm2.GenPrivKey()
	benchmark.BenchmarkVerify(b, priv)
}

func BenchmarkVerifyParallel(b *testing.B) {
	priv := sm2.GenPrivKey()
	benchmark.BenchmarkVerifyParallel(b, priv)
}
