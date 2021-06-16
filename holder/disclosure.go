package holder

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/base45-go/base45"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"time"
)

func (h *Holder) DiscloseAllWithTimeQREncoded(holderSk *big.Int, cred *gabi.Credential, now time.Time) ([]byte, error) {
	proofAsn1, err := h.DiscloseAllWithTime(holderSk, cred, now)
	if err != nil {
		return nil, err
	}

	// Serialize as base45 QR-code
	proofBase45, err := base45.Base45Encode(proofAsn1)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not base45 encode proof", 0)
	}

	// Add prefix
	prefix := []byte{'N', 'L', common.ProofVersionByte, ':'}
	proofPrefixed := append(prefix, proofBase45...)

	return proofPrefixed, nil
}

func (h *Holder) DiscloseAllWithTime(holderSk *big.Int, cred *gabi.Credential, now time.Time) ([]byte, error) {
	attributesAmount := len(cred.Attributes)
	if attributesAmount < 2 {
		return nil, errors.Errorf("Invalid amount of credential attributes")
	}

	// Set the holderSk as first attribute of the credential
	cred.Attributes[0] = holderSk

	// Retrieve the public key from the credential metadata
	err := h.setCredentialPublicKey(cred)
	if err != nil {
		return nil, err
	}

	// Use the time as 'challenge' (that can be precomputed and replayed, indeed)
	disclosureTimeSeconds := now.Unix()
	challenge := common.CalculateTimeBasedChallenge(disclosureTimeSeconds)

	// Build proof that discloses all attributes except the secret key
	var disclosedIndices []int
	for i := 1; i < attributesAmount; i++ {
		disclosedIndices = append(disclosedIndices, i)
	}

	var dpbs gabi.ProofBuilderList
	dpb, err := cred.CreateDisclosureProofBuilder(disclosedIndices, false)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create disclosure proof builder", 0)
	}

	dpbs = append(dpbs, dpb)

	proofList := dpbs.BuildProofList(common.BigOne, challenge, false)
	if len(proofList) != 1 {
		return nil, errors.Errorf("Invalid amount of proofs")
	}

	proof := proofList[0].(*gabi.ProofD)

	// Serialize proof inside an asn.1 structure
	ps := common.ProofSerializationV2{
		DisclosureTimeSeconds: disclosureTimeSeconds,
		C:                     proof.C.Go(),
		A:                     proof.A.Go(),
		EResponse:             proof.EResponse.Go(),
		VResponse:             proof.VResponse.Go(),
		AResponse:             proof.AResponses[0].Go(),
	}

	for i := 1; i < attributesAmount; i++ {
		ps.ADisclosed = append(ps.ADisclosed, proof.ADisclosed[i].Go())
	}

	proofAsn1, err := asn1.Marshal(ps)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not ASN1 marshal proof", 0)
	}

	return proofAsn1, nil
}

func (h *Holder) setCredentialPublicKey(cred *gabi.Credential) error {
	metadataAttributeBytes := common.DecodeAttributeInt(cred.Attributes[1])

	credentialMetadata := &common.CredentialMetadataSerialization{}
	_, err := asn1.Unmarshal(metadataAttributeBytes, credentialMetadata)
	if err != nil {
		return errors.Errorf("Could not unmarshal credential metadata")
	}

	cred.Pk, err = h.findIssuerPk(credentialMetadata.IssuerPkId)
	if err != nil {
		return err
	}

	return nil
}
