package holder

import (
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type Holder struct {
	holderSk  *big.Int
	issuerPks map[string]*gabi.PublicKey
}

func New(holderSk *big.Int, issuerPks map[string]*gabi.PublicKey) *Holder {
	return &Holder{
		holderSk:  holderSk,
		issuerPks: issuerPks,
	}
}

func GenerateSk() *big.Int {
	return common.RandomBigInt(common.GabiSystemParameters.Lm)
}

func (h *Holder) CreateCommitments(pim *common.PrepareIssueMessage) ([]gabi.ProofBuilder, *gabi.IssueCommitmentMessage, error) {
	issuerPk, err := h.findIssuerPk(pim.IssuerPkId)
	if err != nil {
		return nil, nil, err
	}

	holderNonce := common.GenerateNonce()

	credBuilders := make([]gabi.ProofBuilder, 0, pim.CredentialAmount)
	for i := 0; i < pim.CredentialAmount; i++ {
		credBuilder := gabi.NewCredentialBuilder(issuerPk, common.BigOne, h.holderSk, holderNonce, []int{})
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
	credentialAmount := len(credBuilders)
	if credentialAmount != len(ccms) {
		return nil, errors.Errorf("Amount of credential builders doesn't match the amount of create credential messages")
	}

	creds := make([]*gabi.Credential, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		cred, err := constructCredential(credBuilders[i], ccms[i])
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not construct credential", 0)
		}

		creds = append(creds, cred)
	}

	return creds, nil
}

func (h *Holder) ReadCredential(cred *gabi.Credential) (map[string]string, error) {
	attributeAmount := len(cred.Attributes) - 2
	if attributeAmount != len(common.AttributeTypesV2) {
		return nil, errors.Errorf("Unexpected amount of attributes in credential")
	}

	attributes := make(map[string]string)
	for i := 0; i < attributeAmount; i++ {
		attributeType := common.AttributeTypesV2[i]
		attributes[attributeType] = string(common.DecodeAttributeInt(cred.Attributes[i+2]))
	}

	return attributes, nil
}

func (h *Holder) findIssuerPk(issuerPkId string) (*gabi.PublicKey, error) {
	issuerPk, ok := h.issuerPks[issuerPkId]
	if !ok {
		return nil, errors.Errorf("Could not find public key id chosen by issuer")
	}

	return issuerPk, nil
}

func constructCredential(credBuilder gabi.ProofBuilder, ccm *common.CreateCredentialMessage) (*gabi.Credential, error) {
	attributeInts, err := common.ComputeAttributeInts(ccm.Attributes)
	if err != nil {
		return nil, err
	}

	cred, err := credBuilder.(*gabi.CredentialBuilder).ConstructCredential(ccm.IssueSignatureMessage, attributeInts)
	if err != nil {
		return nil, err
	}

	return cred, nil
}
