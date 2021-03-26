package main

// typedef struct {
//   char* value;
//   char* error;
// } Result;
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
)

var issuerKeypairs = map[string]issuer.IssuerKeypair{}

//export LoadIssuerKeypair
func LoadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml string) *C.Result {
	err := loadIssuerKeypair(issuerKeyId, issuerPkXml, issuerSkXml)
	return newResult(nil, err)
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
func GenerateIssuerNonceB64(issuerPkId string) *C.Result {
	val, err := generateIssuerNonceB64(issuerPkId)
	return newResult(val, err)
}

func generateIssuerNonceB64(issuerPkId string) ([]byte, error) {
	inm, err := issuer.GenerateIssuerNonceMessage(issuerPkId)
	if err != nil {
		return nil, errors.Errorf("Could not generate issuer nonce message")
	}

	var issuerNonceB64 []byte
	base64.StdEncoding.Encode(issuerNonceB64, inm)

	return issuerNonceB64, nil
}

//export Issue
func Issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson string) *C.Result {
	val, err := issue(issuerKeyId, issuerNonceMessageB64, commitmentsJson, attributesJson)
	return newResult(val, err)
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
func IssueStaticDisclosureQR(issuerKeyId, attributesJson string) *C.Result {
	val, err := issueStaticDisclosureQR(issuerKeyId, attributesJson)
	return newResult(val, err)
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

func newResult(val []byte, err error) *C.Result {
	var cVal *C.char
	if val != nil {
		cVal = C.CString(string(val))
	} else {
		cVal = nil
	}

	var cErr *C.char
	if err != nil {
		cErr = C.CString(err.Error())
	} else {
		cErr = nil
	}

	return &C.Result{
		value: cVal,
		error: cErr,
	}
}

func main() {

}
