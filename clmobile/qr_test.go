package clmobile

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
	encoded := qrEncode(input)

	decoded, err := qrDecode(encoded)
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
	encoded := qrEncodeAlternative(input)

	decoded, err := qrDecodeAlternative(encoded)
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
	e1 := qrEncode(input)
	e2 := qrEncodeAlternative(input)

	err := bytesMatch(e1, e2)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func BenchmarkQREncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		qrEncode(benchmarkBytes)
	}
}

func BenchmarkQRDecode(b *testing.B) {
	encoded := qrEncode(benchmarkBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := qrDecode(encoded)
		if err != nil {
			b.FailNow()
		}
	}
}

func BenchmarkQREncodeAlternative(b *testing.B) {
	for i := 0; i < b.N; i++ {
		qrEncodeAlternative(benchmarkBytes)
	}
}

func BenchmarkQRDecodeAlternative(b *testing.B) {
	encoded := qrEncode(benchmarkBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := qrDecodeAlternative(encoded)
		if err != nil {
			b.FailNow()
		}
	}
}