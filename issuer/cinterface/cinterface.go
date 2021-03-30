package main

import "C"
import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/holder"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/issuer"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"unsafe"
)

var issuerKeypairs = map[string]issuer.IssuerKeypair{}

//export LoadIssuerKeypair
func LoadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml string, resultBuffer unsafe.Pointer, written *int, error *bool) {
	err := loadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml)
	handleResult(nil, err, resultBuffer, written, error)
}

func loadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml string) error {
	issuerPk, err := gabi.NewPublicKeyFromXML(issuerPkXml)
	if err != nil {
		return errors.WrapPrefix(err, "Could not deserialize issuer public key", 0)
	}

	issuerSk, err := gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		return errors.WrapPrefix(err, "Could not deserialize issuer private key", 0)
	}

	issuerKeypairs[issuerKeyId] = issuer.IssuerKeypair{
		Pk: issuerPk,
		Sk: issuerSk,
	}

	return nil
}

//export GenerateIssuerNonceB64
func GenerateIssuerNonceB64(issuerPkId string, resultBuffer unsafe.Pointer, written *int, error *bool) {
	val, err := generateIssuerNonceB64(issuerPkId)
	handleResult(val, err, resultBuffer, written, error)
}

func generateIssuerNonceB64(issuerPkId string) ([]byte, error) {
	inm, err := issuer.GenerateIssuerNonceMessage(issuerPkId)
	if err != nil {
		return nil, errors.Errorf("Could not generate issuer nonce message")
	}

	var issuerNonceB64 = base64.StdEncoding.EncodeToString(inm)

	return []byte(issuerNonceB64), nil
}

//export Issue
func Issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson string, resultBuffer unsafe.Pointer, written *int, error *bool) {
	val, err := issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson)
	handleResult(val, err, resultBuffer, written, error)
}

func issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson string) ([]byte, error) {
	// Keypair
	issuerKeypair, ok := issuerKeypairs[issuerKeyId]
	if !ok {
		return nil, errors.Errorf("Unknown issuer key id")
	}

	// Nonce message
	issuerNonceMessageBytes, err := base64.StdEncoding.DecodeString(issuerNonceMessageB64)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not base64 deserialize issuerNonceMessage", 0)
	}

	issuerNonceMessage := &common.NonceSerialization{}
	_, err = asn1.Unmarshal(issuerNonceMessageBytes, issuerNonceMessage)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not asn1 deserialize issuerNonceMessage", 0)
	}

	if issuerKeyId != issuerNonceMessage.IssuerPkId {
		return nil, errors.Errorf("The given issuerKeyId doesn't match with the nonce message key id")
	}

	// Commitments
	commitments := new(gabi.IssueCommitmentMessage)
	err = json.Unmarshal([]byte(commitmentsJson), commitments)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not deserialize commitments", 0)
	}

	// Attributes
	var attributes map[string]string
	err = json.Unmarshal([]byte(attributesJson), &attributes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not deserialize attributes", 0)
	}

	// Issuance
	issuerNonce := big.Convert(issuerNonceMessage.Nonce)
	ccm, err := issuer.Issue(issuerKeyId, issuerKeypair, issuerNonce, attributes, commitments)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not issue proof", 0)
	}

	var ccmJson []byte
	ccmJson, err = json.Marshal(ccm)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not serialize create credential message", 0)
	}

	return ccmJson, nil
}

//export IssueStaticDisclosureQR
func IssueStaticDisclosureQR(issuerKeyId, attributesJson string, resultBuffer unsafe.Pointer, written *int, error *bool) {
	val, err := issueStaticDisclosureQR(issuerKeyId, attributesJson)

	handleResult(val, err, resultBuffer, written, error)
}

func issueStaticDisclosureQR(issuerKeyId, attributesJson string) ([]byte, error) {
	// Get issuer keypair
	issuerKeypair, ok := issuerKeypairs[issuerKeyId]
	if !ok {
		return nil, errors.Errorf("Unknown issuer key id")
	}

	// Parse attributes JSON
	var attributes map[string]string
	err := json.Unmarshal([]byte(attributesJson), &attributes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not deserialize attributes", 0)
	}

	// Do the issuance dance by ourselves
	holderSk := holder.GenerateHolderSk()
	issuerNonce := common.GenerateNonce()

	credBuilder, icm := holder.CreateCommitment(issuerKeypair.Pk, issuerNonce, holderSk)
	ccm, err := issuer.Issue(issuerKeyId, issuerKeypair, issuerNonce, attributes, icm)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create credential message", 0)
	}

	var cred *gabi.Credential
	cred, err = holder.CreateCredential(credBuilder, ccm)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create credential from ccm", 0)
	}

	// Disclose and generate QR encoded string
	issuerPks := map[string]*gabi.PublicKey{issuerKeyId: issuerKeypair.Pk}

	var proofAsn1 []byte
	proofAsn1, err = holder.DiscloseAllWithTime(issuerPks, cred) // FIXME: Don't use WithTime here
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not disclose credential", 0)
	}

	qrEncodedProof := common.QrEncode(proofAsn1)
	return qrEncodedProof, nil
}

const BufferSize int = 65536

func handleResult(val []byte, err error, resultBuffer unsafe.Pointer, written *int, error *bool) {
	result := (*[BufferSize]byte)(resultBuffer)[:BufferSize]

	// Store either result or error in the buffer
	bytes := val
	if err == nil {
		*error = false
	} else {
		*error = true
		bytes = []byte(err.Error())
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
