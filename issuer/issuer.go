package issuer

import "C"

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type IssuerKeypair struct {
	Pk *gabi.PublicKey
	Sk *gabi.PrivateKey
}

type IssuanceSession struct {
	SessionId       int
	Nonce           *big.Int
	AttributeValues []string
}

func GenerateIssuerNonceMessage(issuerPkId string) ([]byte, error) {
	res, err := asn1.Marshal(common.NonceSerialization{
		Nonce:      common.GenerateNonce().Go(),
		IssuerPkId: issuerPkId,
	})

	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not serialize nonce", 0)
	}

	return res, nil
}

func Issue(issuerPkId string, issuerKeypair IssuerKeypair, issuerNonce *big.Int, attributes map[string]string, cmmMsg *gabi.IssueCommitmentMessage) (*common.CreateCredentialMessage, error) {
	// Construct metadata attribute
	metadataAttribute, err := asn1.Marshal(common.CredentialMetadataSerialization{
		CredentialVersion: common.CredentialVersion,
		IssuerPkId:        issuerPkId,
	})

	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not serialize credential metadata attribute", 0)
	}

	// Build list of attribute in the correct order
	namedAttributesAmount := len(common.AttributeTypes)

	attributesList := make([][]byte, 0, namedAttributesAmount+1)
	attributesList = append(attributesList, metadataAttribute)

	for i := 0; i < namedAttributesAmount; i++ {
		attributeType := common.AttributeTypes[i]

		v, ok := attributes[attributeType]
		if !ok {
			return nil, errors.Errorf("Required attribute %s was not supplied", attributeType)
		}

		attributesList = append(attributesList, []byte(v))
	}

	// Compute attribute values
	attributeInts, err := common.ComputeAttributeInts(attributesList)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not compute attributes", 0)
	}

	// Instantiate issuer
	issuer := gabi.NewIssuer(issuerKeypair.Sk, issuerKeypair.Pk, common.BigOne)

	// TODO: Verify commitment proofs against issuerNonce

	// Get commitment
	if len(cmmMsg.Proofs) != 1 {
		return nil, errors.Errorf("Incorrect amount of proofs")
	}

	proof, ok := cmmMsg.Proofs[0].(*gabi.ProofU)
	if !ok {
		return nil, errors.Errorf("Received invalid issuance commitment")
	}

	// Compute CL signatures
	ism, err := issuer.IssueSignature(proof.U, attributeInts, nil, cmmMsg.Nonce2, []int{})
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create issue signature", 0)
	}

	return &common.CreateCredentialMessage{
		IssueSignatureMessage: ism,
		Attributes:            attributesList,
	}, nil
}
