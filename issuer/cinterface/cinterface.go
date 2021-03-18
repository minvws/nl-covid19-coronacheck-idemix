package main

import "C"
import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/holder"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/issuer"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var issuerKeypairs = map[string]issuer.IssuerKeypair{}

//export LoadIssuerKeypair
func LoadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml string) *C.char {
	res := loadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml)
	return C.CString(res)
}

func loadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml string) string {
	issuerPk, err := gabi.NewPublicKeyFromXML(issuerPkXml)
	if err != nil {
		return formatError(errors.WrapPrefix(err, "Could not deserialize issuer public key", 0))
	}

	issuerSk, err := gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		return formatError(errors.WrapPrefix(err, "Could not deserialize issuer private key", 0))
	}

	issuerKeypairs[issuerKeyId] = issuer.IssuerKeypair{
		Pk: issuerPk,
		Sk: issuerSk,
	}

	return ""
}

//export GenerateIssuerNonceB64
func GenerateIssuerNonceB64(issuerPkId string) *C.char {
	issuerNonceB64 := base64.StdEncoding.EncodeToString(issuer.GenerateIssuerNonceMessage(issuerPkId))
	return C.CString(issuerNonceB64)
}

//export Issue
func Issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson string) *C.char {
	res := issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson)
	return C.CString(res)
}

func issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson string) string {
	defer func() string {
		if r := recover(); r != nil {
			errorMessage := fmt.Sprintf("Error: %s", r)
			return errorMessage
		} else {
			return "Error: undefined"
		}
	}()

	// Keypair
	issuerKeypair, ok := issuerKeypairs[issuerKeyId]
	if !ok {
		panic("Unknown issuer key id")
	}

	// Nonce message
	issuerNonceMessageBytes, err := base64.StdEncoding.DecodeString(issuerNonceMessageB64)
	if err != nil {
		panic("Could not base64 deserialize issuerNonceMessage")
	}

	issuerNonceMessage := &common.NonceSerialization{}
	_, err = asn1.Unmarshal(issuerNonceMessageBytes, issuerNonceMessage)
	if err != nil {
		panic("Could not asn1 deserialize issuerNonceMessage")
	}

	if issuerKeyId != issuerNonceMessage.IssuerPkId {
		panic("The given issuerKeyId doesn't match with the nonce message key id")
	}

	// Commitments
	commitments := new(gabi.IssueCommitmentMessage)
	err = json.Unmarshal([]byte(commitmentsJson), commitments)
	if err != nil {
		panic("Could not deserialize commitments")
	}

	// Attributes
	var attributes map[string]string
	err = json.Unmarshal([]byte(attributesJson), &attributes)
	if err != nil {
		panic( "Could not deserialize attributes")
	}

	// Issuance
	issuerNonce := big.Convert(issuerNonceMessage.Nonce)
	ccm := issuer.Issue(issuerKeyId, issuerKeypair, issuerNonce, attributes, commitments)

	var ccmJson []byte
	ccmJson, err = json.Marshal(ccm)
	if err != nil {
		panic("Could not serialize create credential message")
	}

	return string(ccmJson)
}

//export IssueStaticDisclosureQR
func IssueStaticDisclosureQR(issuerKeyId, attributesJson string) *C.char {
	res := issueStaticDisclosureQR(issuerKeyId, attributesJson)
	return C.CString(res)
}

func issueStaticDisclosureQR(issuerKeyId, attributesJson string) string {
	// Get issuer keypair
	issuerKeypair, ok := issuerKeypairs[issuerKeyId]
	if !ok {
		return formatError(errors.Errorf("Unknown issuer key id"))
	}

	// Parse attributes JSON
	var attributes map[string]string
	err := json.Unmarshal([]byte(attributesJson), &attributes)
	if err != nil {
		return formatError(errors.WrapPrefix(err, "Could not deserialize attributes", 0))
	}

	// Do the issuance dance by ourselves
	holderSk := holder.GenerateHolderSk()
	issuerNonce := common.GenerateNonce()

	credBuilder, icm := holder.CreateCommitment(issuerKeypair.Pk, issuerNonce, holderSk)
	ccm := issuer.Issue(issuerKeyId, issuerKeypair, issuerNonce, attributes, icm)

	var cred *gabi.Credential
	cred, err = holder.CreateCredential(credBuilder, ccm)
	if err != nil {
		return formatError(errors.WrapPrefix(err, "Could not create credential from ccm", 0))
	}

	// Disclose and generate QR encoded string
	issuerPks := map[string]*gabi.PublicKey{issuerKeyId: issuerKeypair.Pk}

	var proofAsn1 []byte
	proofAsn1, err = holder.DiscloseAllWithTime(issuerPks, cred) // FIXME: Don't use WithTime here
	if err != nil {
		return formatError(errors.WrapPrefix(err, "Could not disclose credential", 0))
	}

	qrEncodedProof := common.QrEncode(proofAsn1)
	return string(qrEncodedProof)
}

func formatError(err error) string {
	return fmt.Sprintf("Error: %s", err.Error())
}

func main() {

}
