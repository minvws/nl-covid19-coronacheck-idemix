package localsigner

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type LocalSigner struct {
	PkId string
	Pk   *gabi.PublicKey

	sk *gabi.PrivateKey
}

func New(pkId, pkPath, skPath string) (*LocalSigner, error) {
	pk, err := gabi.NewPublicKeyFromFile(pkPath)
	if err != nil {
		msg := fmt.Sprintf("Could not load public key from file %s", pkPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	sk, err := gabi.NewPrivateKeyFromFile(skPath, false)
	if err != nil {
		msg := fmt.Sprintf("Could not load private key from file %s", skPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	return &LocalSigner{
		PkId: pkId,
		Pk:   pk,
		sk:   sk,
	}, nil
}

func NewFromString(pkId, pkXML, skXML string) (*LocalSigner, error) {
	pk, err := gabi.NewPublicKeyFromXML(pkXML)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not load public key from string", 0)
	}

	sk, err := gabi.NewPrivateKeyFromXML(skXML, false)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not load private key from string", 0)
	}

	return &LocalSigner{
		PkId: pkId,
		Pk:   pk,
		sk:   sk,
	}, nil
}

func (ls *LocalSigner) PrepareSign() (pkId string, issuerNonce *big.Int, err error) {
	return ls.PkId, common.GenerateNonce(), nil
}

func (ls *LocalSigner) Sign(credentialsAttributes [][]*big.Int, proofUs []*big.Int, holderNonce *big.Int) (isms []*gabi.IssueSignatureMessage, err error) {
	credentialAmount := len(credentialsAttributes)
	if credentialAmount != len(proofUs) {
		return nil, errors.Errorf("Amount of credentials doesn't match amount of proofUs")
	}

	gabiSigner := gabi.NewIssuer(ls.sk, ls.Pk, common.BigOne)

	isms = make([]*gabi.IssueSignatureMessage, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		ism, err := gabiSigner.IssueSignature(proofUs[i], credentialsAttributes[i], nil, holderNonce, []int{})
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not create gabi signature", 0)
		}

		isms = append(isms, ism)
	}

	return isms, nil
}
