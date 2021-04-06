package clmobile

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
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

var lastCredBuilder *gabi.CredentialBuilder

func CreateCommitmentMessage(holderSkJson, issuerNonceMessageBase64 []byte) *Result {
	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()}
	}

	issuerNonceMessageBytes, err := base64.StdEncoding.DecodeString(string(issuerNonceMessageBase64))
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not base64 unmarshal issuer nonce message", 0).Error()}
	}

	issuerNonceMessage := &common.NonceSerialization{}
	_, err = asn1.Unmarshal(issuerNonceMessageBytes, issuerNonceMessage)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not asn1 unmarshal issuer nonce message", 0).Error()}
	}

	issuerPk, ok := loadedIssuerPks[issuerNonceMessage.IssuerPkId]
	if !ok {
		return &Result{nil, errors.Errorf("Public key chosen by issuer is unknown").Error()}
	}

	var icm *gabi.IssueCommitmentMessage
	lastCredBuilder, icm = holder.CreateCommitment(issuerPk, big.Convert(issuerNonceMessage.Nonce), holderSk)

	icmJson, err := json.Marshal(icm)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not marshal IssueCommitmentMessage", 0).Error()}
	}

	return &Result{icmJson, ""}
}

func CreateCredential(holderSkJson, ccmJson []byte) *Result {
	credBuilder := lastCredBuilder
	lastCredBuilder = nil

	if credBuilder == nil {
		return &Result{nil, errors.Errorf("CreateCommitMessage should be called before CreateCredential").Error()}
	}

	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()}
	}

	ccm := &common.CreateCredentialMessage{}
	err = json.Unmarshal(ccmJson, ccm)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal CreateCredentialMessage", 0).Error()}
	}

	cred, err := holder.CreateCredential(credBuilder, ccm)
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

	return &Result{common.QrEncode(r.Value), ""}
}

func DiscloseAllWithTime(credJson []byte) *Result {
	cred := new(gabi.Credential)
	err := json.Unmarshal(credJson, cred)
	if err != nil {
		return &Result{nil, errors.WrapPrefix(err, "Could not unmarshal credential", 0).Error()}
	}

	proofAsn1, err := holder.DiscloseAllWithTime(loadedIssuerPks, cred)
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
	proofAsn1, err := common.QrDecode(proofQrEncodedAsn1)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not decode QR", 0).Error()}
	}

	return Verify(proofAsn1)
}

func Verify(proofAsn1 []byte) *VerifyResult {
	attributes, unixTimeSeconds, err := verifier.Verify(loadedIssuerPks, proofAsn1)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not verify proof", 0).Error()}
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return &VerifyResult{nil, 0, errors.WrapPrefix(err, "Could not marshal attributes", 0).Error()}
	}

	return &VerifyResult{attributesJson, unixTimeSeconds, ""}
}
