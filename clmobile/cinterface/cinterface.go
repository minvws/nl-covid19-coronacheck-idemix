package main

import "C"
import (
	"github.com/minvws/nl-covid19-coronacheck-cl-core/clmobile"
	"unsafe"
)

//export LoadIssuerPks
func LoadIssuerPks(annotatedPksJson string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.LoadIssuerPks([]byte(annotatedPksJson))
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export GenerateHolderSk
func GenerateHolderSk(resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.GenerateHolderSk()
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export CreateCommitmentMessage
func CreateCommitmentMessage(holderSkJson, issuerNonceMessageBase64 string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.CreateCommitmentMessage([]byte(holderSkJson), []byte(issuerNonceMessageBase64))
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export CreateCredential
func CreateCredential(holderSkJson, ccmJson string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.CreateCredential([]byte(holderSkJson), []byte(ccmJson))
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export ReadCredential
func ReadCredential(credJson string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.ReadCredential([]byte(credJson))
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export DiscloseAllWithTimeQrEncoded
func DiscloseAllWithTimeQrEncoded(holderSkJson, credJson string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.DiscloseAllWithTimeQrEncoded([]byte(holderSkJson), []byte(credJson))
	handleResult(r.Value, r.Error, resultBuffer, bufferLength, written, error)
}

//export DiscloseAllWithTime
func DiscloseAllWithTime(credJson string, resultBuffer unsafe.Pointer, bufferLength int, written *int, error *bool) {
	var r = clmobile.DiscloseAllWithTime([]byte(credJson))
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