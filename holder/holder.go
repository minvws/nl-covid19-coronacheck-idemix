package holder

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"time"
)

func GenerateHolderSk() *big.Int {
	return common.RandomBigInt(common.GabiSystemParameters.Lm)
}

func CreateCommitment(issuerPk *gabi.PublicKey, issuerNonce, holderSk *big.Int) (*gabi.CredentialBuilder, *gabi.IssueCommitmentMessage) {
	credBuilder, icm := createCommitments(issuerPk, issuerNonce, holderSk)
	return credBuilder, icm
}

func CreateCredential(credBuilder *gabi.CredentialBuilder, ccm *common.CreateCredentialMessage) (*gabi.Credential, error) {
	cred, err := constructCredential(credBuilder, ccm)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not construct credential", 0)
	}

	return cred, nil
}

func ReadCredential(cred *gabi.Credential) (map[string]string, error) {
	attributeAmount := len(cred.Attributes) - 2
	if attributeAmount != len(common.AttributeTypes) {
		return nil, errors.Errorf("Unexpected amount of attributes in credential")
	}

	attributes := make(map[string]string)
	for i := 0; i < attributeAmount; i++ {
		attributeType := common.AttributeTypes[i]
		attributes[attributeType] = string(common.DecodeAttributeInt(cred.Attributes[i+2]))
	}

	return attributes, nil
}

func DiscloseAll(issuerPks map[string]*gabi.PublicKey, cred *gabi.Credential, challenge *big.Int) ([]byte, error) {
	return Disclose(issuerPks, cred, maximumDisclosureChoices(cred), challenge)
}

func DiscloseAllWithTime(issuerPks map[string]*gabi.PublicKey, cred *gabi.Credential) ([]byte, error) {
	return DiscloseWithTime(issuerPks, cred, maximumDisclosureChoices(cred))
}

func maximumDisclosureChoices(cred *gabi.Credential) []bool {
	choices := make([]bool, len(cred.Attributes)-2)
	for i := range choices {
		choices[i] = true
	}

	return choices
}

func DiscloseWithTime(issuerPks map[string]*gabi.PublicKey, cred *gabi.Credential, disclosureChoices []bool) ([]byte, error) {
	return disclose(issuerPks, cred, disclosureChoices, nil)
}

func Disclose(issuerPks map[string]*gabi.PublicKey, cred *gabi.Credential, disclosureChoices []bool, challenge *big.Int) ([]byte, error) {
	if challenge == nil {
		return nil, errors.Errorf("No challenge was provided")
	}

	return disclose(issuerPks, cred, disclosureChoices, challenge)
}

func disclose(issuerPks map[string]*gabi.PublicKey, cred *gabi.Credential, disclosureChoices []bool, challenge *big.Int) ([]byte, error) {
	// The first attribute (which is the secret key) can never be disclosed
	// The second attribute (which is the metadata attribute) is always disclosed
	disclosureChoices = append([]bool{false, true}, disclosureChoices...)

	attributesAmount := len(cred.Attributes)
	if len(disclosureChoices) != attributesAmount || attributesAmount < 2 {
		return nil, errors.Errorf("Invalid amount of disclosure choices or credential attributes")
	}

	// Retrieve the public key from the credential metadata
	metadataAttributeBytes := []byte(common.DecodeAttributeInt(cred.Attributes[1]))

	credentialMetadata := &common.CredentialMetadataSerialization{}
	_, err := asn1.Unmarshal(metadataAttributeBytes, credentialMetadata)
	if err != nil {
		return nil, errors.Errorf("Could not unmarshal credential metadata")
	}

	var ok bool
	cred.Pk, ok = issuerPks[credentialMetadata.IssuerPkId]
	if !ok {
		return nil, errors.Errorf("No public key known for this credential")
	}

	// Calculate indexes of disclosed attributes
	var disclosedIndices []int
	for i, disclosed := range disclosureChoices {
		if disclosed {
			disclosedIndices = append(disclosedIndices, i)
		}
	}

	// If no challenge is provided, use a time-based 'challenge', and
	// save the time in the serialization of the proof
	ps := common.ProofSerialization{}
	if challenge == nil {
		ps.UnixTimeSeconds = time.Now().Unix()
		challenge = common.CalculateTimeBasedChallenge(ps.UnixTimeSeconds)
	}

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

	// Serialize proof
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

func createCommitments(issuerPk *gabi.PublicKey, issuerNonce, holderSk *big.Int) (*gabi.CredentialBuilder, *gabi.IssueCommitmentMessage) {
	credBuilder, holderNonce := issuanceProofBuilders(issuerPk, holderSk)

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{credBuilder})
	icm := &gabi.IssueCommitmentMessage{
		Proofs: builders.BuildProofList(common.BigOne, issuerNonce, false),
		Nonce2: holderNonce,
	}

	return credBuilder, icm
}

func issuanceProofBuilders(issuerPk *gabi.PublicKey, holderSk *big.Int) (*gabi.CredentialBuilder, *big.Int) {
	holderNonce := common.GenerateNonce()
	credBuilder := gabi.NewCredentialBuilder(issuerPk, common.BigOne, holderSk, holderNonce, []int{})

	return credBuilder, holderNonce
}

func constructCredential(credBuilder *gabi.CredentialBuilder, ccm *common.CreateCredentialMessage) (*gabi.Credential, error) {
	attributeInts, err := common.ComputeAttributeInts(ccm.Attributes)
	if err != nil {
		return nil, err
	}

	cred, err := credBuilder.ConstructCredential(ccm.IssueSignatureMessage, attributeInts)
	if err != nil {
		return nil, err
	}

	return cred, nil
}
