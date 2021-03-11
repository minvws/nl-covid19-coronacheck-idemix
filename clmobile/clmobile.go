package clmobile

import (
	"encoding/base64"
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/holder"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/verifier"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var loadedIssuerPks map[string]*gabi.PublicKey
var HasLoadedIssuerPks bool = false

type Result struct {
	Value []byte
	Error string
}

type AnnotatedPk struct {
	Id    string `json:"id"`
	PkXml []byte `json:"public_key"`
}

func LoadIssuerPks(annotatedPksJson []byte) *Result {
	// Unmarshal JSON list of keys
	annotatedPks := make([]AnnotatedPk, 0)
	err := json.Unmarshal(annotatedPksJson, &annotatedPks)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal annotated issuer public keys", 0).Error()}
	}

	// Unmarshal base64 XML-encoded keys
	// Allow unmarshalling errors to allow for forward-compatibility
	pks := map[string]*gabi.PublicKey{}
	for _, annotatedPk := range annotatedPks {
		pk, err := gabi.NewPublicKeyFromXML(string(annotatedPk.PkXml))
		if err != nil {
			continue
		}

		pks[annotatedPk.Id] = pk
	}

	if len(pks) == 0 {
		return &Result{nil, errors.Errorf("No valid public keys were supplied").Error()}
	}

	loadedIssuerPks = pks
	HasLoadedIssuerPks = true

	return &Result{nil, ""}
}

func GenerateHolderSk() *Result {
	holderSkJson, err := json.Marshal(holder.GenerateHolderSk())
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not serialize holder secret key", 0).Error()}
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
	for _, issuerPk = range loadedIssuerPks {
	}

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
	for _, cred.Pk = range loadedIssuerPks {
	}

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
	for _, issuerPk = range loadedIssuerPks {
	}

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
