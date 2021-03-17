package main

import "C"
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/issuer"
	"github.com/privacybydesign/gabi"
)

//export GenerateIssuerNonceB64
func GenerateIssuerNonceB64(issuerPkId string) *C.char {
	issuerNonceB64 := base64.StdEncoding.EncodeToString(issuer.GenerateIssuerNonceMessage(issuerPkId))
	return C.CString(issuerNonceB64)
}

//export Issue
func Issue(issuerPkId, issuerPkXml, issuerSkXml, issuerNonceMessageB64, commitmentsJson, attributesJson string) *C.char {
	defer func() *C.char {
		if r := recover(); r != nil {
			errorMessage := fmt.Sprintf("Error: %s", r)
			return C.CString(errorMessage)
		} else {
			return C.CString("Error: undefined")
		}
	}()

	issuerNonceMessage, err := base64.StdEncoding.DecodeString(issuerNonceMessageB64)
	if err != nil {
		panic("Could not deserialize issuerNonceMessage")
	}

	// Attributes
	var attributes map[string]string
	err = json.Unmarshal([]byte(attributesJson), &attributes)
	if err != nil {
		panic("Could not deserialize attributes")
	}

	// Commitments
	commitments := new(gabi.IssueCommitmentMessage)
	err = json.Unmarshal([]byte(commitmentsJson), commitments)
	if err != nil {
		panic("Could not deserialize commitments")
	}

	sig := issuer.Issue(issuerPkId, issuerPkXml, issuerSkXml, issuerNonceMessage, attributes, commitments)
	sigBytes, _ := json.Marshal(sig)
	sigString := string(sigBytes)

	return C.CString(sigString)
}

func main() {

}
