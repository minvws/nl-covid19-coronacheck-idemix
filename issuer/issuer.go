package issuer

import "C"

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type IssuanceSession struct {
	SessionId       int
	Nonce           *big.Int
	AttributeValues []string
}

func GenerateIssuerNonceMessage(issuerPkId string) []byte {
	res, err := asn1.Marshal(common.NonceSerialization{
		Nonce:      common.GenerateNonce().Go(),
		IssuerPkId: issuerPkId,
	})

	if err != nil {
		panic(errors.WrapPrefix(err, "Could not serialize nonce", 0).Error())
	}

	return res
}

func Issue(issuerPkId, issuerPkXml, issuerSkXml string, issuerNonceMessage []byte, attributes map[string]string, cmmMsg *gabi.IssueCommitmentMessage) *common.CreateCredentialMessage {
	issuerPk, err := gabi.NewPublicKeyFromXML(issuerPkXml)
	if err != nil {
		panic("Could not deserialize issuer public key")
	}

	issuerSk, err := gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		panic("Could not deserialize issuer private key")
	}

	return issue(issuerPkId, issuerPk, issuerSk, issuerNonceMessage, attributes, cmmMsg)
}

func issue(issuerPkId string, issuerPk *gabi.PublicKey, issuerSk *gabi.PrivateKey, issuerNonceMessage []byte, attributes map[string]string, cmmMsg *gabi.IssueCommitmentMessage) *common.CreateCredentialMessage {
	// Construct metadata attribute
	metadataAttribute, err := asn1.Marshal(common.CredentialMetadataSerialization{
		CredentialVersion: common.CredentialVersion,
		IssuerPkId:        issuerPkId,
	})

	if err != nil {
		panic(errors.WrapPrefix(err, "Could not serialize credential metadata attribute", 0).Error())
	}

	// Build list of attribute in the correct order
	namedAttributesAmount := len(common.AttributeTypes)

	attributesList := make([][]byte, 0, namedAttributesAmount+1)
	attributesList = append(attributesList, metadataAttribute)

	for i := 0; i < namedAttributesAmount; i++ {
		attributeType := common.AttributeTypes[i]

		v, ok := attributes[attributeType]
		if !ok {
			panic(errors.Errorf("Required attribute %s was not supplied", attributeType).Error())
		}

		attributesList = append(attributesList, []byte(v))
	}

	// Compute attribute values
	attributeInts, err := common.ComputeAttributeInts(attributesList)
	if err != nil {
		panic("Error during computing attributes: " + err.Error())
	}

	// Instantiate issuer
	issuer := gabi.NewIssuer(issuerSk, issuerPk, common.BigOne)

	// TODO: Verify commitment proofs against issuerNonce

	// Get commitment
	if len(cmmMsg.Proofs) != 1 {
		panic("Incorrect amount of proofs")
	}

	proof, ok := cmmMsg.Proofs[0].(*gabi.ProofU)
	if !ok {
		panic("Received invalid issuance commitment")
	}

	// Compute CL signatures
	ism, err := issuer.IssueSignature(proof.U, attributeInts, nil, cmmMsg.Nonce2, []int{})
	if err != nil {
		panic("Issuance failed: " + err.Error())
	}

	return &common.CreateCredentialMessage{
		IssueSignatureMessage: ism,
		Attributes:            attributesList,
	}
}
