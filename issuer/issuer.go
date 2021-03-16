package issuer

import "C"

import (
	"github.com/minvws/nl-covid19-coronacheck-cl-core/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type IssuanceSession struct {
	SessionId       int
	Nonce           *big.Int
	AttributeValues []string
}

func GenerateIssuerNonce() *big.Int {
	return common.GenerateNonce()
}

func Issue(issuerPkId, issuerPkXml, issuerSkXml string, issuerNonce *big.Int, attributes map[string]string, cmmMsg *gabi.IssueCommitmentMessage) *gabi.IssueSignatureMessage {
	issuerPk, err := gabi.NewPublicKeyFromXML(issuerPkXml)
	if err != nil {
		panic("Could not deserialize issuer public key")
	}

	issuerSk, err := gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		panic("Could not deserialize issuer private key")
	}

	return issue(issuerPkId, issuerPk, issuerSk, issuerNonce, attributes, cmmMsg)
}

func issue(issuerPkId string, issuerPk *gabi.PublicKey, issuerSk *gabi.PrivateKey, issuerNonce *big.Int, attributes map[string]string, cmmMsg *gabi.IssueCommitmentMessage) *gabi.IssueSignatureMessage {
	// Compute attribute values
	attributeInts, err := common.ComputeAttributes(attributes)
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
	return ism
}
