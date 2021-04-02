package main

import "C"
import (
	"github.com/minvws/nl-covid19-coronacheck-cl-core/clmobile"
	"unsafe"
)

//export LoadIssuerPks
func LoadIssuerPks(annotatedPksJson []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.LoadIssuerPks(annotatedPksJson)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export GenerateHolderSk
func GenerateHolderSk(resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.GenerateHolderSk()
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export CreateCommitmentMessage
func CreateCommitmentMessage(holderSkJson, issuerNonceMessageBase64 []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.CreateCommitmentMessage(holderSkJson, issuerNonceMessageBase64)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export CreateCredential
func CreateCredential(holderSkJson, ccmJson []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.CreateCredential(holderSkJson, ccmJson)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export ReadCredential
func ReadCredential(credJson []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.ReadCredential(credJson)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export DiscloseAllWithTimeQrEncoded
func DiscloseAllWithTimeQrEncoded(holderSkJson, credJson []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.DiscloseAllWithTimeQrEncoded(holderSkJson, credJson)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export DiscloseAllWithTime
func DiscloseAllWithTime(credJson []byte, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.DiscloseAllWithTime(credJson)
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

const BufferSize int = 65536

func handleResult(val []byte, err string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	// Handle buffer size mismatch
	if bufferLength != BufferSize {
		*error = true
		return
	}

	result := (*[BufferSize]byte)(resultBuffer)[:BufferSize]

	// Store either result or error in the buffer
	bytes := val
	if len(err) == 0 {
		*error = false
	} else {
		*error = true
		bytes = []byte(err)
	}

	// Handle *void* result
	if bytes == nil	{
		*written = 0
		return
	}

	// Handle value-result or error-result
	copy(result, bytes)
	*written = len(bytes)
}

func main() {

}
