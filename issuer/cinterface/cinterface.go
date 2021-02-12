package main

import "C"
import (
	"encoding/json"
	"fmt"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/common"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
)

//export GenerateIssuerNonceB64
func GenerateIssuerNonceB64() *C.char {
	issuerNonceB64, err := json.Marshal(issuer.GenerateIssuerNonce())
	if err != nil {
		panic("Could not serialize issuer nonce")
	}

	return C.CString(string(issuerNonceB64))
}

//export Issue
func Issue(issuerPkXml, issuerSkXml, issuerNonceB64, commitmentsJson, attributesJson string) *C.char {
	defer func() *C.char {
		if r := recover(); r != nil {
			errorMessage := fmt.Sprintf("Error: %s", r)
			return C.CString(errorMessage)
		} else {
			return C.CString("Error: undefined")
		}
	}()

	issuerNonce := new(big.Int)
	err := issuerNonce.UnmarshalJSON([]byte(issuerNonceB64))
	if err != nil {
		panic("Could not deserialize issuerNonce")
	}

	if issuerNonce.BitLen() != int(common.GabiSystemParameters.Lstatzk) {
		panic("Invalid length for issuerNonce")
	}

	// Attributes
	var attributes []string
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

	sig := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributes, commitments)
	sigBytes, _ := json.Marshal(sig)
	sigString := string(sigBytes)

	return C.CString(sigString)
}

func main() {

}
