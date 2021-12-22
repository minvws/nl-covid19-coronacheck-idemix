package holder

import (
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type Holder struct {
	findIssuerPk common.FindIssuerPkFunc

	// createCredentialVersion is the only version the the holder will construct new credentials for
	createCredentialVersion int
}

func New(findIssuerPk common.FindIssuerPkFunc, createCredentialVersion int) *Holder {
	return &Holder{
		findIssuerPk:            findIssuerPk,
		createCredentialVersion: createCredentialVersion,
	}
}

func GenerateSk() *big.Int {
	return common.RandomBigInt(common.GabiSystemParameters.Lm)
}

func (h *Holder) CreateCommitments(holderSk *big.Int, pim *common.PrepareIssueMessage) ([]gabi.ProofBuilder, *gabi.IssueCommitmentMessage, error) {
	issuerPk, err := h.findIssuerPk(pim.IssuerPkId)
	if err != nil {
		return nil, nil, err
	}

	holderNonce := common.GenerateNonce()

	credBuilders := make([]gabi.ProofBuilder, 0, pim.CredentialAmount)
	for i := 0; i < pim.CredentialAmount; i++ {
		credBuilder := gabi.NewCredentialBuilder(issuerPk, common.BigOne, holderSk, holderNonce, []int{})
		credBuilders = append(credBuilders, credBuilder)
	}

	builders := gabi.ProofBuilderList(credBuilders)
	icm := &gabi.IssueCommitmentMessage{
		Proofs: builders.BuildProofList(common.BigOne, pim.IssuerNonce, false),
		Nonce2: holderNonce,
	}

	return credBuilders, icm, nil
}

func (h *Holder) CreateCredentials(credBuilders []gabi.ProofBuilder, ccms []*common.CreateCredentialMessage) ([]*gabi.Credential, error) {
	credentialAmount := len(ccms)
	if credentialAmount > len(credBuilders) {
		return nil, errors.Errorf("More credentials are being issued than there are proof builders")
	}

	creds := make([]*gabi.Credential, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		cred, err := h.constructCredential(credBuilders[i], ccms[i])
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not construct credential", 0)
		}

		// Remove holder secret key from credential attributes
		cred.Attributes[0] = nil

		// Read credential to verify its version
		_, version, err := h.ReadCredential(cred)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not read freshly constructed credential", 0)
		}

		if version != h.createCredentialVersion {
			return nil, errors.Errorf("Invalid credential version in freshly constructed credential")
		}

		creds = append(creds, cred)
	}

	return creds, nil
}

func (h *Holder) ReadCredential(cred *gabi.Credential) (attributes map[string]string, version int, err error) {
	// Validate that at least the secret key and metadata attribute is present
	attributeAmount := len(cred.Attributes)
	if attributeAmount < 2 {
		return nil, 0, errors.Errorf("Unexpected amount of attributes in credential")
	}

	// Decode metadata to retrieve credential version and attribute types
	credentialVersion, _, attributeTypes, err := common.DecodeMetadataAttribute(cred.Attributes[1])
	if err != nil {
		return nil, 0, err
	}

	// Verify amount of named attributes
	namedAttributeAmount := attributeAmount - 2
	if namedAttributeAmount != len(attributeTypes) {
		return nil, 0, errors.Errorf("Unexpected amount of named attributes in credential")
	}

	// Decode and insert every attribute
	attributes = make(map[string]string)
	for i := 0; i < namedAttributeAmount; i++ {
		attributeType := attributeTypes[i]
		attributes[attributeType] = string(common.DecodeAttributeInt(cred.Attributes[i+2]))
	}

	return attributes, credentialVersion, nil
}

func (h *Holder) constructCredential(credBuilder gabi.ProofBuilder, ccm *common.CreateCredentialMessage) (*gabi.Credential, error) {
	attributeTypes := common.AttributeTypes[h.createCredentialVersion]
	attributeInts, err := common.ComputeAttributeInts(attributeTypes, ccm.Attributes)
	if err != nil {
		return nil, err
	}

	cred, err := credBuilder.(*gabi.CredentialBuilder).ConstructCredential(ccm.IssueSignatureMessage, attributeInts)
	if err != nil {
		return nil, err
	}

	return cred, nil
}
