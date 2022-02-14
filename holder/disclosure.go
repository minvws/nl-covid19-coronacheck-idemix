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

func (h *Holder) DiscloseWithTimeQREncoded(holderSk *big.Int, cred *gabi.Credential, hideCategory bool, now time.Time) (qr, proofIdentifier []byte, err error) {
	proofAsn1, proofIdentifier, err := h.DiscloseWithTime(holderSk, cred, hideCategory, now)
	if err != nil {
		return nil, nil, err
	}

	// Serialize as base45 QR-code
	proofBase45, err := base45.Base45Encode(proofAsn1)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not base45 encode proof", 0)
	}

	// Add prefix
	prefix := []byte{'N', 'L', common.ProofVersionByteV3, ':'}
	qr = append(prefix, proofBase45...)

	return qr, proofIdentifier, nil
}

func (h *Holder) DiscloseWithTime(holderSk *big.Int, cred *gabi.Credential, hideCategory bool, now time.Time) (proofAsn1, proofIdentifier []byte, err error) {
	attributesAmount := len(cred.Attributes)
	if attributesAmount < 2 {
		return nil, nil, errors.Errorf("Invalid amount of credential attributes")
	}

	// Set the holderSk as first attribute of the credential
	cred.Attributes[0] = holderSk

	// Decode the metadata attribute and gather version and public key
	_, issuerPkId, attributeTypes, err := common.DecodeMetadataAttribute(cred.Attributes[1])
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not decode metadata attribute", 0)
	}

	if len(attributeTypes) != attributesAmount-2 {
		return nil, nil, errors.Errorf("Unexpected amount of attributes in credential")
	}

	// Retrieve and set the public key from the metadata
	cred.Pk, err = h.findIssuerPk(issuerPkId)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could find issuer public key", 0)
	}

	// Use the time as 'challenge' (that can be precomputed and replayed, indeed)
	disclosureTimeSeconds := now.Unix()
	challenge := common.CalculateTimeBasedChallenge(disclosureTimeSeconds)

	// Build proof that discloses all attributes including the metadata,
	//  but except the secret key and possibly the category
	disclosedIndices := []int{1}
	for i, attributeType := range attributeTypes {
		if !hideCategory || attributeType != "category" {
			disclosedIndices = append(disclosedIndices, i+2)
		}
	}

	var dpbs gabi.ProofBuilderList
	dpb, err := cred.CreateDisclosureProofBuilder(disclosedIndices, false)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Failed to create disclosure proof builder", 0)
	}

	dpbs = append(dpbs, dpb)

	proofList := dpbs.BuildProofList(common.BigOne, challenge, false)
	if len(proofList) != 1 {
		return nil, nil, errors.Errorf("Invalid amount of proofs")
	}

	proof := proofList[0].(*gabi.ProofD)

	// Serialize proof inside an asn.1 structure
	ps := common.ProofSerializationV3{
		DisclosureTimeSeconds: disclosureTimeSeconds,
		C:                     proof.C.Go(),
		A:                     proof.A.Go(),
		EResponse:             proof.EResponse.Go(),
		VResponse:             proof.VResponse.Go(),
	}

	ps.AResponses = append(ps.AResponses, proof.AResponses[0].Go())
	ps.ADisclosed = append(ps.ADisclosed, proof.ADisclosed[1].Go())
	for i, attributeType := range attributeTypes {
		if !hideCategory || attributeType != "category" {
			ps.ADisclosed = append(ps.ADisclosed, proof.ADisclosed[i+2].Go())
		} else {
			ps.AResponses = append(ps.AResponses, proof.AResponses[i+2].Go())
		}
	}

	proofAsn1, err = asn1.Marshal(ps)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not ASN1 marshal proof", 0)
	}

	// Calculate proof identifier
	proofIdentifier = common.CalculateProofIdentifier(proof)

	return proofAsn1, proofIdentifier, nil
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
