package clmobile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var issuerPks map[string]*gabi.PublicKey

type Result struct {
	Value []byte
	Error string
}

func LoadIssuerPks(issuerPkIds []string, issuerPkXmls [][]byte) *Result {
	issuerPkLen := len(issuerPkIds)
	if issuerPkLen != len(issuerPkXmls) {
		return &Result{nil, errors.Errorf("Amount of public key ids doesn't match amount of XML strings").Error()}
	}

	issuerPks = map[string]*gabi.PublicKey{}

	for i := 0; i < issuerPkLen; i++ {
		issuerPkId := issuerPkIds[i]
		issuerPkXml := issuerPkXmls[i]

		issuerPk, err := gabi.NewPublicKeyFromXML(string(issuerPkXml))
		if err != nil {
			errMsg := fmt.Sprintf("Could not unmarshal public key %d", i)
			return &Result{nil, errors.WrapPrefix(err, errMsg, 0).Error()}
		}

		issuerPks[issuerPkId] = issuerPk
	}

	return &Result{nil, ""}
}

func GenerateHolderSk() *Result {
	holderSkJson, err := json.Marshal(holder.GenerateHolderSk())
	if err != nil {
		return &Result{nil, errors.Errorf("Could not serialize holder secret key").Error()}
	}

	return &Result{holderSkJson, ""}
}

// TODO: Handle state properly
var dirtyHack *gabi.CredentialBuilder

func CreateCommitmentMessage(holderSkJson, issuerNonceBase64 []byte) *Result {
	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()}
	}

	issuerNonce, err := base64DecodeBigInt(issuerNonceBase64)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal issuer nonce", 0).Error()}
	}

	// FIXME: Fork gabi to allow Pk to change at a later stage
	var issuerPk *gabi.PublicKey
	for _, issuerPk = range issuerPks {}

	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)
	dirtyHack = credBuilder // FIXME

	icmJson, err := json.Marshal(icm)
	if err != nil {
		panic("Could not marshal IssueCommitmentMessage")
	}

	return &Result{icmJson, ""}
}

type CreateCredentialMessage struct {
	IssueSignatureMessage *gabi.IssueSignatureMessage `json:"ism"`
	Attributes            map[string]string           `json:"attributes"`
}

func CreateCredential(holderSkJson, ccmJson []byte) *Result {
	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()}
	}

	ccm := &CreateCredentialMessage{}
	err = json.Unmarshal(ccmJson, ccm)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal CreateCredentialMessage", 0).Error()}
	}

	credBuilder := dirtyHack // FIXME

	cred, err := holder.CreateCredential(credBuilder, ccm.IssueSignatureMessage, ccm.Attributes)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not create credential", 0).Error()}
	}

	credJson, err := json.Marshal(cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not marshal credential", 0).Error()}
	}

	return &Result{credJson, ""}
}

func ReadCredential(credJson []byte) *Result {
	cred := new(gabi.Credential)
	err := json.Unmarshal(credJson, cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal credential", 0).Error()}
	}

	attributes, err := holder.ReadCredential(cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not read credential", 0).Error()}
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could marshal attributes", 0).Error()}
	}

	return &Result{attributesJson, ""}
}

func DiscloseAllWithTimeQrEncoded(holderSkJson, credJson []byte) *Result {
	r := DiscloseAllWithTime(credJson)
	if r.Error != "" {
		return r
	}

	return &Result{qrEncode(r.Value), ""}
}

func DiscloseAllWithTime(credJson []byte) *Result {
	cred := new(gabi.Credential)
	err := json.Unmarshal(credJson, cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal credential", 0).Error()}
	}

	// FIXME: Get Pk out of credential metadata
	for _, cred.Pk = range issuerPks {}

	proofAsn1, err := holder.DiscloseAllWithTime(cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not create proof", 0).Error()}
	}

	return &Result{proofAsn1, ""}
}

type VerifyResult struct {
	AttributesJson  []byte
	UnixTimeSeconds int64
	Error           string
}

func VerifyQREncoded(proofQrEncodedAsn1 []byte) *VerifyResult {
	proofAsn1, err := qrDecode(proofQrEncodedAsn1)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not decode QR", 0).Error()}
	}

	return Verify(proofAsn1)
}

func Verify(proofAsn1 []byte) *VerifyResult {
	// FIXME: Get Pk out of credential metadata
	var issuerPk *gabi.PublicKey
	for _, issuerPk = range issuerPks {}

	attributes, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not verify proof", 0).Error()}
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not marshal attributes", 0).Error()}
	}

	return &VerifyResult{attributesJson, unixTimeSeconds, ""}
}

func base64DecodeBigInt(b64 []byte) (*big.Int, error) {
	bts := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(bts, b64)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not decode bigint", 0)
	}

	i := new(big.Int)
	i.SetBytes(bts[0:n])

	return i, nil
}
