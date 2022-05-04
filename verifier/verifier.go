package verifier

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/base45-go/base45"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	gobig "math/big"
)

type Verifier struct {
	findIssuerPk common.FindIssuerPkFunc
}

type VerifiedCredential struct {
	Attributes            map[string]string
	DisclosureTimeSeconds int64
	IssuerPkId            string
	CredentialVersion     int
	ProofIdentifier       []byte
}

func New(findIssuerPk common.FindIssuerPkFunc) *Verifier {
	return &Verifier{
		findIssuerPk: findIssuerPk,
	}
}

func (v *Verifier) VerifyQREncoded(proof []byte) (verifiedCredential *VerifiedCredential, err error) {
	// Get serialization version and verify before decoding
	proofVersionByte, proofBase45, err := common.ExtractProofVersion(proof)
	if err != nil {
		return nil, err
	}

	if proofVersionByte != common.ProofVersionByteV2 && proofVersionByte != common.ProofVersionByteV3 {
		return nil, errors.Errorf("Unsupported proof version")
	}

	// Decode base45
	proofAsn1, err := base45.Base45Decode(proofBase45)
	if err != nil {
		return nil, errors.Errorf("Could not base45 decode v2 proof")
	}

	// Deserialize the asn.1 structure. Upgrade V2 serializations to V3 first.
	var ps *common.ProofSerializationV3
	if proofVersionByte == common.ProofVersionByteV2 {
		ps, err = deserializeV2ToV3(proofAsn1)
	} else if proofVersionByte == common.ProofVersionByteV3 {
		ps, err = deserializeV3(proofAsn1)
	} else {
		return nil, errors.Errorf("Unreachable unsupported proof version")
	}

	if err != nil {
		return nil, err
	}

	// Verify the proof
	verifiedCredential, err = v.verify(ps)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not verify proof", 0)
	}

	return verifiedCredential, nil
}

func deserializeV2ToV3(proofAsn1 []byte) (*common.ProofSerializationV3, error) {
	ps := &common.ProofSerializationV2{}
	_, err := asn1.Unmarshal(proofAsn1, ps)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal v2 proof")
	}

	// Upgrade to V3
	return &common.ProofSerializationV3{
		DisclosureTimeSeconds: ps.DisclosureTimeSeconds,
		C:                     ps.C,
		A:                     ps.A,
		EResponse:             ps.EResponse,
		VResponse:             ps.VResponse,
		AResponses:            []*gobig.Int{ps.AResponse},
		ADisclosed:            ps.ADisclosed,
	}, nil
}

func deserializeV3(proofAsn1 []byte) (*common.ProofSerializationV3, error) {
	ps := &common.ProofSerializationV3{}
	_, err := asn1.Unmarshal(proofAsn1, ps)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal v3 proof")
	}

	return ps, nil
}

func (v *Verifier) verify(ps *common.ProofSerializationV3) (*VerifiedCredential, error) {
	// Decode metadata attribute
	disclosedAmount := len(ps.ADisclosed)
	hiddenAmount := len(ps.AResponses)
	if disclosedAmount < 1 {
		return nil, errors.Errorf("The metadata attribute must be disclosed")
	}

	_, _, attributeTypes, err := common.DecodeMetadataAttribute(big.Convert(ps.ADisclosed[0]))
	if err != nil {
		return nil, err
	}

	// Ensure the amount of attributes matches the disclosed (minus metadata) plus hidden (minus secret key)
	namedAttributeAmount := len(attributeTypes)
	if (disclosedAmount-1)+(hiddenAmount-1) != namedAttributeAmount {
		return nil, errors.Errorf("Invalid amount of disclosures")
	}

	// In addition to the secret key, only the category may be hidden
	if hiddenAmount < 1 || hiddenAmount > 2 {
		return nil, errors.Errorf("Invalid amount of hidden attributes")
	}

	// Build proof with disclosures and responses, where only the category can be hidden
	proof := &gabi.ProofD{
		C:          big.Convert(ps.C),
		A:          big.Convert(ps.A),
		EResponse:  big.Convert(ps.EResponse),
		VResponse:  big.Convert(ps.VResponse),
		AResponses: map[int]*big.Int{0: big.Convert(ps.AResponses[0])},
		ADisclosed: map[int]*big.Int{},
	}

	for i, disclosed := range ps.ADisclosed {
		proof.ADisclosed[1+i] = big.Convert(disclosed)
	}

	for i, hidden := range ps.AResponses[1:] {
		proof.AResponses[1+disclosedAmount+i] = big.Convert(hidden)
	}

	return v.verifyProofD(proof, ps.DisclosureTimeSeconds)
}

func (v *Verifier) verifyProofD(proof *gabi.ProofD, disclosureTimeSeconds int64) (*VerifiedCredential, error) {
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
		ProofIdentifier:       common.CalculateProofIdentifier(proof),
	}, nil
}
