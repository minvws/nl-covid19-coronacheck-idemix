package issuer

import (
	"encoding/asn1"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
	"time"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/minvws/nl-covid19-coronacheck-idemix/holder"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	gabipool "github.com/privacybydesign/gabi/pool"
)

type Signer interface {
	PrepareSign(keySpecification *localsigner.KeySpecification) (pkId string, issuerNonce *big.Int, err error)
	Sign(keySpecification *localsigner.KeySpecification, credentialsAttributeList [][]*big.Int, proofUs []*big.Int, holderNonce *big.Int) (isms []*gabi.IssueSignatureMessage, err error)
	FindIssuerPk(keySpecification *localsigner.KeySpecification) (pk *gabi.PublicKey, kid string, err error)
	GetPrimePool() gabipool.PrimePool
}

type Issuer struct {
	Signer Signer
}

type PrepareIssueRequestMessage struct {
	KeyIdentifier    string `json:"keyIdentifier"`
	CredentialAmount int    `json:"credentialAmount"`

	// DEPRECATED: This field is deprecated and should be removed when callers have been migrated
	KeyUsage string `json:"keyUsage"`
}

type IssueMessage struct {
	PrepareIssueMessage    *common.IssueSpecificationMessage `json:"prepareIssueMessage"`
	IssueCommitmentMessage *gabi.IssueCommitmentMessage      `json:"issueCommitmentMessage"`
	CredentialsAttributes  []map[string]string               `json:"credentialsAttributes"`
	CredentialVersion      int                               `json:"credentialVersion"`
	KeyIdentifier          string                            `json:"keyIdentifier"`

	// DEPRECATED: This field is deprecated and should be removed when callers have been migrated
	KeyUsage string `json:"keyUsage"`
}

type StaticIssueMessage struct {
	CredentialAttributes map[string]string `json:"credentialAttributes"`
	CredentialVersion    int               `json:"credentialVersion"`
	KeyIdentifier        string            `json:"keyIdentifier"`

	// DEPRECATED: This field is deprecated and should be removed when callers have been migrated
	KeyUsage string `json:"keyUsage"`
}

func New(signer Signer) *Issuer {
	return &Issuer{
		Signer: signer,
	}
}

func (iss *Issuer) PrepareIssue(pir *PrepareIssueRequestMessage) (*common.IssueSpecificationMessage, error) {
	issuerPkId, issuerNonce, err := iss.Signer.PrepareSign(pir.buildSpecification())
	if err != nil {
		return nil, err
	}

	return &common.IssueSpecificationMessage{
		IssuerPkId:       issuerPkId,
		IssuerNonce:      issuerNonce,
		CredentialAmount: pir.CredentialAmount,
	}, nil
}

func (iss *Issuer) Issue(im *IssueMessage) ([]*common.CreateCredentialMessage, error) {
	// We need at least as much commitments as there are credentials issued
	// Any additional commitments are just ignored
	credentialAmount := len(im.CredentialsAttributes)
	commitmentAmount := len(im.IssueCommitmentMessage.Proofs)
	if credentialAmount > commitmentAmount {
		return nil, errors.Errorf("More credentials are being issued than commitments have been supplied")
	}

	// Build the metadata attribute that is present in every credential, for the requested credential version
	metadataAttribute, err := buildMetadataAttribute(im.CredentialVersion, im.PrepareIssueMessage.IssuerPkId)
	if err != nil {
		return nil, err
	}

	// Get the public key that is used, and check that it matches the prepare issue message
	pk, kid, err := iss.Signer.FindIssuerPk(im.buildSpecification())
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not find public key that is used to issue credentials", 0)
	}

	if im.PrepareIssueMessage.IssuerPkId != kid {
		return nil, errors.Errorf("Key specified by usage doesn't match prepare issue message public key id")
	}

	// For every credential, convert the the attribute map to a list of attribute ints,
	// and extract the proofU out of the commitment
	// TODO: Extract this fugly mess out into proper structures
	credentialsAttributeByteList := make([][][]byte, 0, credentialAmount)
	credentialsAttributeIntList := make([][]*big.Int, 0, credentialAmount)
	proofUs := make([]*big.Int, 0, credentialAmount)
	proofs := make([]gabi.Proof, 0, commitmentAmount)
	pks := make([]*gabi.PublicKey, 0, commitmentAmount)

	for i := 0; i < commitmentAmount; i++ {
		proofU, ok := im.IssueCommitmentMessage.Proofs[i].(*gabi.ProofU)
		if !ok {
			return nil, errors.Errorf("Could not recognize issue commitment")
		}

		// Collect proofs to verify against, for all commitments
		proofs = append(proofs, proofU)
		pks = append(pks, pk)

		// Build credential bytes, ints and gather proofs
		if i >= credentialAmount {
			continue
		}

		attributesMap := im.CredentialsAttributes[i]
		attributesBytes, attributesInts, err := computeAttributesList(im.CredentialVersion, attributesMap, metadataAttribute)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not compute attributes list", 0)
		}

		credentialsAttributeByteList = append(credentialsAttributeByteList, attributesBytes)
		credentialsAttributeIntList = append(credentialsAttributeIntList, attributesInts)
		proofUs = append(proofUs, proofU.U)
	}

	// Make sure the commitments verify against the previously created nonce
	if !gabi.ProofList(proofs).Verify(pks, common.BigOne, im.PrepareIssueMessage.IssuerNonce, false, nil) {
		return nil, errors.Errorf("Holder commitments did did not verify against nonce")
	}

	// Sign all credentials
	isms, err := iss.Signer.Sign(im.buildSpecification(), credentialsAttributeIntList, proofUs, im.IssueCommitmentMessage.Nonce2)
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

func (iss *Issuer) IssueStatic(sim *StaticIssueMessage) (proofPrefixed, proofIdentifier []byte, err error) {
	// Prepare issuance
	ks := sim.buildSpecification()

	pim, err := iss.PrepareIssue(&PrepareIssueRequestMessage{
		CredentialAmount: 1,
		KeyIdentifier:    ks.KeyIdentifier,
		KeyUsage:         ks.KeyUsage,
	})
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not create prepare issue message", 0)
	}

	// Get key for issuance, and construct a trivial function for the holder to retrieve the key
	pk, _, err := iss.Signer.FindIssuerPk(sim.buildSpecification())
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not find public key to issue static credential", 0)
	}

	findIssuerPkFunc := func(_ string) (*gabi.PublicKey, error) { return pk, nil }

	// Create a single commitment
	h := holder.New(findIssuerPkFunc, sim.CredentialVersion)
	holderSk := holder.GenerateSk()
	credBuilders, icm, err := h.CreateCommitments(holderSk, pim)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not create commitment", 0)
	}

	// Issue and create credentials
	ccms, err := iss.Issue(&IssueMessage{
		PrepareIssueMessage:    pim,
		IssueCommitmentMessage: icm,
		CredentialsAttributes:  []map[string]string{sim.CredentialAttributes},
		CredentialVersion:      sim.CredentialVersion,
		KeyUsage:               sim.KeyUsage,
		KeyIdentifier:          sim.KeyIdentifier,
	})
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not issue static credential", 0)
	}
	creds, err := h.CreateCredentials(credBuilders, ccms)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not create static credential", 0)
	}

	credAmount := len(creds)
	if credAmount != 1 {
		return nil, nil, errors.Errorf("Expected only a single credential, got %d instead", credAmount)
	}

	// Disclose to create the QR, with a zero disclosure timestamp
	proofPrefixed, proofIdentifier, err = h.DiscloseWithTimeQREncoded(holderSk, creds[0], false, time.Unix(0, 0))
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not disclose credential", 0)
	}

	return proofPrefixed, proofIdentifier, nil
}

func buildMetadataAttribute(credentialVersion int, issuerPkId string) (metadataAttribute []byte, err error) {
	metadataAttribute, err = asn1.Marshal(common.CredentialMetadataSerialization{
		CredentialVersion: []byte{byte(credentialVersion)},
		IssuerPkId:        issuerPkId,
	})

	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not serialize credential metadata attribute", 0)
	}

	return metadataAttribute, nil
}

func computeAttributesList(credentialVersion int, attributesMap map[string]string, metadataAttribute []byte) ([][]byte, []*big.Int, error) {
	// Build list of attribute in the correct order, with the metadata attribute prepended
	attributeTypes, ok := common.AttributeTypes[credentialVersion]
	if !ok {
		return nil, nil, errors.Errorf("The provided credentials version is not supported")
	}

	namedAttributesAmount := len(attributeTypes)

	attributesBytes := make([][]byte, 0, namedAttributesAmount+1)
	attributesBytes = append(attributesBytes, metadataAttribute)

	for i := 0; i < namedAttributesAmount; i++ {
		attributeType := attributeTypes[i]

		v, ok := attributesMap[attributeType]
		if !ok {
			return nil, nil, errors.Errorf("Required attribute %s was not supplied", attributeType)
		}

		attributesBytes = append(attributesBytes, []byte(v))
	}

	// Compute attribute values
	attributesInts, err := common.ComputeAttributeInts(attributeTypes, attributesBytes)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not compute attributes", 0)
	}

	return attributesBytes, attributesInts, nil
}

// DEPRECATED: This struct is function and should be removed when callers have been migrated
func (pir *PrepareIssueRequestMessage) buildSpecification() *localsigner.KeySpecification {
	return &localsigner.KeySpecification{
		KeyIdentifier: pir.KeyIdentifier,
		KeyUsage:      pir.KeyUsage,
	}
}

// DEPRECATED: This struct is temporary and should be removed when callers have been migrated
func (im *IssueMessage) buildSpecification() *localsigner.KeySpecification {
	return &localsigner.KeySpecification{
		KeyIdentifier: im.KeyIdentifier,
		KeyUsage:      im.KeyUsage,
	}
}

// DEPRECATED: This struct is temporary and should be removed when callers have been migrated
func (sim *StaticIssueMessage) buildSpecification() *localsigner.KeySpecification {
	return &localsigner.KeySpecification{
		KeyIdentifier: sim.KeyIdentifier,
		KeyUsage:      sim.KeyUsage,
	}
}
