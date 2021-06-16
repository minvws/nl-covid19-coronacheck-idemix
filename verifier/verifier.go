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
	findIssuerPk common.FindIssuerPkFunc
}

type VerifiedCredential struct {
	Attributes            map[string]string
	DisclosureTimeSeconds int64
	IssuerPkId            string
	CredentialVersion     int
}

func New(findIssuerPk common.FindIssuerPkFunc) *Verifier {
	return &Verifier{
		findIssuerPk: findIssuerPk,
	}
}

func (v *Verifier) VerifyQREncoded(proof []byte) (*VerifiedCredential, error) {
	// Verify with the v2 proof serialization format
	proofVersionByte, proofBase45, err := extractProofVersion(proof)
	if err == nil {
		if proofVersionByte != common.ProofVersionByte {
			return nil, errors.Errorf("Unsupported proof version")
		}

		proofAsn1, err := base45.Base45Decode(proofBase45)
		if err != nil {
			return nil, errors.Errorf("Could not base45 decode v2 proof")
		}

		verifiedCredential, err := v.VerifyV2(proofAsn1)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not verify v2 proof", 0)
		}

		return verifiedCredential, nil
	}

	// Try to verify with the v1 serialization
	proofAsn1, err := base45.Base45Decode(proof)
	if err != nil {
		return nil, errors.Errorf("Could not base45 decode v1 proof")
	}

	verifiedCredential, err := v.VerifyV1(proofAsn1)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not verify v1 proof", 0)
	}

	return verifiedCredential, nil
}

func (v *Verifier) VerifyV1(proofAsn1 []byte) (*VerifiedCredential, error) {
	// Deserialize proof
	ps := &common.ProofSerializationV1{}
	_, err := asn1.Unmarshal(proofAsn1, ps)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal proof")
	}

	// Decode metadata attribute up front, separate from the rest of the logic
	// It must be the first disclosed attribute
	if len(ps.ADisclosed) < 1 {
		return nil, errors.Errorf("The metadata attribute must be disclosed")
	}

	_, _, attributeTypes, err := common.DecodeMetadataAttribute(big.Convert(ps.ADisclosed[0]))
	if err != nil {
		return nil, err
	}

	// Make sure the amount of disclosure choices match the amount of attributes, plus secret key and metadata
	attributeAmount := len(attributeTypes) + 2
	if len(ps.DisclosureChoices) != attributeAmount {
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

	// Create a proofD structure
	proof := &gabi.ProofD{
		C:          big.Convert(ps.C),
		A:          big.Convert(ps.A),
		EResponse:  big.Convert(ps.EResponse),
		VResponse:  big.Convert(ps.VResponse),
		AResponses: aResponses,
		ADisclosed: aDisclosed,
	}

	return v.VerifyCommon(proof, ps.DisclosureTimeSeconds)
}

func (v *Verifier) VerifyV2(proofAsn1 []byte) (*VerifiedCredential, error) {
	// Deserialize proof
	ps := &common.ProofSerializationV2{}
	_, err := asn1.Unmarshal(proofAsn1, ps)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal proof")
	}

	// Decode metadata attribute
	disclosedAmount := len(ps.ADisclosed)
	if disclosedAmount < 1 {
		return nil, errors.Errorf("The metadata attribute must be disclosed")
	}

	_, _, attributeTypes, err := common.DecodeMetadataAttribute(big.Convert(ps.ADisclosed[0]))
	if err != nil {
		return nil, err
	}

	// See if there are enough disclosures, including the metadata attribute
	namedAttributeAmount := len(attributeTypes)
	if disclosedAmount != namedAttributeAmount+1 {
		return nil, errors.Errorf("Invalid amount of disclosures; expected %d disclosures", namedAttributeAmount)
	}

	// Build proof
	aDisclosed := map[int]*big.Int{}
	for i := 0; i < disclosedAmount; i++ {
		aDisclosed[i+1] = big.Convert(ps.ADisclosed[i])
	}

	proof := &gabi.ProofD{
		C:          big.Convert(ps.C),
		A:          big.Convert(ps.A),
		EResponse:  big.Convert(ps.EResponse),
		VResponse:  big.Convert(ps.VResponse),
		AResponses: map[int]*big.Int{0: big.Convert(ps.AResponse)},
		ADisclosed: aDisclosed,
	}

	return v.VerifyCommon(proof, ps.DisclosureTimeSeconds)
}

func (v *Verifier) VerifyCommon(proof *gabi.ProofD, disclosureTimeSeconds int64) (*VerifiedCredential, error) {
	// Get metadata attribute (again)
	credentialVersion, issuerPkId, attributeTypes, err := common.DecodeMetadataAttribute(proof.ADisclosed[1])
	if err != nil {
		return nil, err
	}

	// Find public key
	issuerPk, err := v.findIssuerPk(issuerPkId)
	if err != nil {
		return nil, err
	}

	// Verify with the given timestamp
	var proofList gabi.ProofList
	proofList = append(proofList, proof)

	timeBasedChallenge := common.CalculateTimeBasedChallenge(disclosureTimeSeconds)
	valid := proofList.Verify([]*gabi.PublicKey{issuerPk}, common.BigOne, timeBasedChallenge, false, []string{})

	if !valid {
		return nil, errors.Errorf("Invalid proof")
	}

	// Retrieve attribute values
	attributes := make(map[string]string)
	for disclosureIndex, d := range proof.ADisclosed {
		// Exclude metadata attribute
		if disclosureIndex == 1 {
			continue
		}

		attributeType := attributeTypes[disclosureIndex-2]
		attributes[attributeType] = string(common.DecodeAttributeInt(d))
	}

	return &VerifiedCredential{
		Attributes:            attributes,
		DisclosureTimeSeconds: disclosureTimeSeconds,
		IssuerPkId:            issuerPkId,
		CredentialVersion:     credentialVersion,
	}, nil
}

func HasNLPrefix(bts []byte) bool {
	_, _, err := extractProofVersion(bts)
	return err == nil
}

func extractProofVersion(proofPrefixed []byte) (proofVersionByte byte, proofBase45 []byte, err error) {
	if len(proofPrefixed) < 4 {
		return 0x00, nil, errors.Errorf("Could not process abnormally short QR")
	}

	if proofPrefixed[0] != 'N' || proofPrefixed[1] != 'L' || proofPrefixed[3] != ':' {
		return 0x00, nil, errors.Errorf("QR is not prefixed as an NL entry proof")
	}

	proofVersionByte = proofPrefixed[2]
	if !((proofVersionByte >= '0' && proofVersionByte <= '9') || (proofVersionByte >= 'A' && proofVersionByte <= 'Z')) {
		return 0x00, nil, errors.Errorf("QR has invalid context id byte")
	}

	return proofVersionByte, proofPrefixed[4:], nil
}
