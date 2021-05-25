package issuer

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type Signer interface {
	PrepareSign() (pkId string, issuerNonce *big.Int, err error)
	Sign(credentialsAttributeList [][]*big.Int, proofUs []*big.Int, holderNonce *big.Int) (isms []*gabi.IssueSignatureMessage, err error)
}

type Issuer struct {
	signer Signer
}

type IssueMessage struct {
	PrepareIssueMessage    *common.PrepareIssueMessage  `json:"prepareIssueMessage"`
	IssueCommitmentMessage *gabi.IssueCommitmentMessage `json:"issueCommitmentMessage"`
	CredentialsAttributes  []map[string]string          `json:"credentialsAttributes"`
}

func New(signer Signer) *Issuer {
	return &Issuer{
		signer: signer,
	}
}

func (iss *Issuer) PrepareIssue(credentialAmount int) (*common.PrepareIssueMessage, error) {
	issuerPkId, issuerNonce, err := iss.signer.PrepareSign()
	if err != nil {
		return nil, err
	}

	return &common.PrepareIssueMessage{
		IssuerPkId:       issuerPkId,
		IssuerNonce:      issuerNonce,
		CredentialAmount: credentialAmount,
	}, nil
}

func (iss *Issuer) Issue(im *IssueMessage) ([]*common.CreateCredentialMessage, error) {
	credentialAmount := len(im.CredentialsAttributes)
	if credentialAmount != len(im.IssueCommitmentMessage.Proofs) {
		return nil, errors.Errorf("The amount of commitments doesn't match amount of credentials")
	}

	// Build the metadata attribute that is present in every credential
	metadataAttribute, err := buildMetadataAttribute(im.PrepareIssueMessage.IssuerPkId)
	if err != nil {
		return nil, err
	}

	// For every credential, convert the the attribute map to a list of attribute ints,
	// and extract the proofU out of the commitment
	// TODO: Extract this fugly mess out into proper structures
	credentialsAttributeByteList := make([][][]byte, 0, credentialAmount)
	credentialsAttributeIntList := make([][]*big.Int, 0, credentialAmount)
	proofUs := make([]*big.Int, 0, credentialAmount)

	for i := 0; i < credentialAmount; i++ {
		attributesMap := im.CredentialsAttributes[i]
		attributesBytes, attributesInts, err := computeAttributesList(attributesMap, metadataAttribute)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not compute attributes list", 0)
		}

		proofU, ok := im.IssueCommitmentMessage.Proofs[i].(*gabi.ProofU)
		if !ok {
			return nil, errors.Errorf("Could not recognize issue commitment")
		}

		credentialsAttributeByteList = append(credentialsAttributeByteList, attributesBytes)
		credentialsAttributeIntList = append(credentialsAttributeIntList, attributesInts)
		proofUs = append(proofUs, proofU.U)
	}

	// Sign all credentials
	isms, err := iss.signer.Sign(credentialsAttributeIntList, proofUs, im.IssueCommitmentMessage.Nonce2)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not sign", 0)
	}

	if credentialAmount != len(isms) {
		return nil, errors.Errorf("The amount of signatures doesn't match the amount of credentials")
	}

	// Map the signatures to createCredentialMessages
	ccms := make([]*common.CreateCredentialMessage, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		ccm := &common.CreateCredentialMessage{
			IssueSignatureMessage: isms[i],
			Attributes:            credentialsAttributeByteList[i],
		}

		ccms = append(ccms, ccm)
	}

	return ccms, nil
}

func buildMetadataAttribute(issuerPkId string) (metadataAttribute []byte, err error) {
	metadataAttribute, err = asn1.Marshal(common.CredentialMetadataSerialization{
		CredentialVersion: common.CredentialVersion,
		IssuerPkId:        issuerPkId,
	})

	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not serialize credential metadata attribute", 0)
	}

	return metadataAttribute, nil
}

func computeAttributesList(attributesMap map[string]string, metadataAttribute []byte) ([][]byte, []*big.Int, error) {
	// Build list of attribute in the correct order, with the metadata attribute prepended
	namedAttributesAmount := len(common.AttributeTypesV2)

	attributesBytes := make([][]byte, 0, namedAttributesAmount+1)
	attributesBytes = append(attributesBytes, metadataAttribute)

	for i := 0; i < namedAttributesAmount; i++ {
		attributeType := common.AttributeTypesV2[i]

		v, ok := attributesMap[attributeType]
		if !ok {
			return nil, nil, errors.Errorf("Required attribute %s was not supplied", attributeType)
		}

		attributesBytes = append(attributesBytes, []byte(v))
	}

	// Compute attribute values
	attributesInts, err := common.ComputeAttributeInts(attributesBytes)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not compute attributes", 0)
	}

	return attributesBytes, attributesInts, nil
}
