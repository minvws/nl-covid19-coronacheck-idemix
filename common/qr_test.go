package common

import (
	"github.com/go-errors/errors"
	"math/rand"
	"testing"
)

func genBytes() []byte {
	b := make([]byte, 1024)
	rand.Read(b)

	return b
}

func bytesMatch(b1, b2 []byte) error {
	if len(b1) != len(b2) {
		return errors.Errorf("Lengths don't match")
	}

	for i := 0; i < len(b1); i++ {
		if b1[i] != b2[i] {
			return errors.Errorf("Contents don't match")
		}
	}

	return nil
}

var benchmarkBytes = genBytes()

func TestQrEncodeDecode(t *testing.T) {
	input := genBytes()
	encoded := QrEncode(input)

	decoded, err := QrDecode(encoded)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = bytesMatch(input, decoded)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestQrEncodeDecodeAlternative(t *testing.T) {
	input := genBytes()
	encoded := QrEncodeAlternative(input)

	decoded, err := QrDecodeAlternative(encoded)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = bytesMatch(input, decoded)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestQRImplementationCorrespondence(t *testing.T) {
	input := genBytes()
	e1 := QrEncode(input)
	e2 := QrEncodeAlternative(input)

	err := bytesMatch(e1, e2)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func BenchmarkQREncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		QrEncode(benchmarkBytes)
	}
}

func BenchmarkQRDecode(b *testing.B) {
	encoded := QrEncode(benchmarkBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := QrDecode(encoded)
		if err != nil {
			b.FailNow()
		}
	}
}

func BenchmarkQREncodeAlternative(b *testing.B) {
	for i := 0; i < b.N; i++ {
		QrEncodeAlternative(benchmarkBytes)
	}
}

func BenchmarkQRDecodeAlternative(b *testing.B) {
	encoded := QrEncode(benchmarkBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := QrDecodeAlternative(encoded)
		if err != nil {
			b.FailNow()
		}
	}
}
