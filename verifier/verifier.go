package verifier

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/base45-go/base45"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type Verifier struct {
	issuerPks map[string]*gabi.PublicKey
}

type VerifiedCredential struct {
	Attributes        map[string]string
	UnixTimeSeconds   int64
	IssuerPkId        string
	CredentialVersion int
}

func New(issuerPks map[string]*gabi.PublicKey) *Verifier {
	return &Verifier{
		issuerPks: issuerPks,
	}
}

func (v *Verifier) VerifyQREncoded(proofBase45 []byte) (*VerifiedCredential, error) {
	proofAsn1, err := base45.Base45Decode(proofBase45)
	if err != nil {
		return nil, errors.Errorf("Could not base45 decode proof")
	}

	return v.Verify(proofAsn1)
}

func (v *Verifier) Verify(proofAsn1 []byte) (*VerifiedCredential, error) {
	// Deserialize proof
	ps := &common.ProofSerialization{}
	_, err := asn1.Unmarshal(proofAsn1, ps)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal proof")
	}

	// Make sure the amount of disclosure choices match the amount of attributes, plus secret key and metadata
	numAttributes := len(common.AttributeTypesV1) + 2
	if len(ps.DisclosureChoices) != numAttributes {
		return nil, errors.Errorf("Invalid amount of disclosure choices")
	}

	// Validate that the secret key is not marked as disclosed, and the metadata is marked as disclosed
	if ps.DisclosureChoices[0] {
		return nil, errors.Errorf("First attribute (secret key) should never be disclosed")
	}

	if !ps.DisclosureChoices[1] {
		return nil, errors.Errorf("Second attribute (metadata) should be disclosed")
	}

	// Convert the lists of disclosures and non-disclosure responses to a
	// map from attribute index -> disclosure/response, while checking bounds
	aDisclosed, aResponses := map[int]*big.Int{}, map[int]*big.Int{}

	numDisclosures := len(ps.ADisclosed)
	numResponses := len(ps.AResponses)
	di, ri := 0, 0

	for i, disclosureChoice := range ps.DisclosureChoices {
		if disclosureChoice {
			if di >= numDisclosures {
				return nil, errors.Errorf("Incongruent amount of disclosures")
			}
			aDisclosed[i] = big.Convert(ps.ADisclosed[di])
			di++
		} else {
			if ri >= numResponses {
				return nil, errors.Errorf("Incongruent amount of non-disclosure responses")
			}
			aResponses[i] = big.Convert(ps.AResponses[ri])
			ri++
		}
	}

	// Retrieve the metadata attribute and get the correct public key
	credentialVersion, issuerPkId, err := common.DecodeMetadataAttribute(aDisclosed[1])
	if err != nil {
		return nil, err
	}

	issuerPk, ok := v.issuerPks[issuerPkId]
	if !ok {
		return nil, errors.Errorf("Could not find public key referenced by credential")
	}

	// Create a proofD structure
	proof := &gabi.ProofD{
		C:          big.Convert(ps.C),
		A:          big.Convert(ps.A),
		EResponse:  big.Convert(ps.EResponse),
		VResponse:  big.Convert(ps.VResponse),
		AResponses: aResponses,
		ADisclosed: aDisclosed,
	}

	var proofList gabi.ProofList
	proofList = append(proofList, proof)

	// Verify with the given timestamp
	timeBasedChallenge := common.CalculateTimeBasedChallenge(ps.UnixTimeSeconds)
	valid := proofList.Verify([]*gabi.PublicKey{issuerPk}, common.BigOne, timeBasedChallenge, false, []string{})

	if !valid {
		return nil, errors.Errorf("Invalid proof")
	}

	// Retrieve attribute values
	attributes := make(map[string]string)
	for disclosureIndex, d := range aDisclosed {
		// Exclude metadata attribute
		if disclosureIndex == 1 {
			continue
		}

		attributeType := common.AttributeTypesV2[disclosureIndex-2]
		attributes[attributeType] = string(common.DecodeAttributeInt(d))
	}

	return &VerifiedCredential{
		Attributes:        attributes,
		UnixTimeSeconds:   ps.UnixTimeSeconds,
		IssuerPkId:        issuerPkId,
		CredentialVersion: credentialVersion,
	}, nil
}
