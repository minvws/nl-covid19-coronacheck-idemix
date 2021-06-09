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

	return proofBase45, nil
}

func (h *Holder) DiscloseAllWithTime(holderSk *big.Int, cred *gabi.Credential, now time.Time) ([]byte, error) {
	attributesAmount := len(cred.Attributes)
	if attributesAmount < 2 {
		return nil, errors.Errorf("Invalid amount of credential attributes")
	}

	// Set the holderSk as first attribute of the credential
	cred.Attributes[0] = holderSk

	// The first attribute (which is the holder secret key) can never be disclosed
	// The second attribute (which is the metadata attribute) is always disclosed
	disclosureChoices := []bool{false, true}
	disclosedIndices := []int{1}

	for i := 2; i < attributesAmount; i++ {
		disclosureChoices = append(disclosureChoices, true)
		disclosedIndices = append(disclosedIndices, i)
	}

	// Retrieve the public key from the credential metadata
	err := h.setCredentialPublicKey(cred)
	if err != nil {
		return nil, err
	}

	// Use the time as 'challenge' (that can be precomputed and replayed, indeed)
	ps := common.ProofSerialization{}
	ps.UnixTimeSeconds = now.Unix()

	challenge := common.CalculateTimeBasedChallenge(ps.UnixTimeSeconds)

	// Build proof
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
	ps.Version = common.ProofSerializationVersion
	ps.DisclosureChoices = disclosureChoices
	ps.C = proof.C.Go()
	ps.A = proof.A.Go()
	ps.EResponse = proof.EResponse.Go()
	ps.VResponse = proof.VResponse.Go()

	for i, disclosed := range disclosureChoices {
		if disclosed {
			ps.ADisclosed = append(ps.ADisclosed, proof.ADisclosed[i].Go())
		} else {
			ps.AResponses = append(ps.AResponses, proof.AResponses[i].Go())
		}
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
