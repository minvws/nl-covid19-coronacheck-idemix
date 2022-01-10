package localsigner

import (
	"fmt"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"

	gabipool "github.com/privacybydesign/gabi/pool"
)

type Key struct {
	PkId   string `mapstructure:"public-key-id"`
	PkPath string `mapstructure:"public-key-path"`
	SkPath string `mapstructure:"private-key-path"`

	pk *gabi.PublicKey
	sk *gabi.PrivateKey
}

type LocalSigner struct {
	UsageKeys map[string]*Key
	Pool      gabipool.PrimePool
}

func New(usageKeys map[string]*Key, pool gabipool.PrimePool) (*LocalSigner, error) {
	ls := &LocalSigner{
		UsageKeys: usageKeys,
		Pool:      pool,
	}

	err := ls.loadKeys()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not load local signer keys", 0)
	}

	return ls, nil
}

func (ls *LocalSigner) loadKeys() error {
	var err error
	for _, key := range ls.UsageKeys {
		key.pk, err = gabi.NewPublicKeyFromFile(key.PkPath)
		if err != nil {
			msg := fmt.Sprintf("Could not load public key from file %s", key.PkPath)
			return errors.WrapPrefix(err, msg, 0)
		}

		key.sk, err = gabi.NewPrivateKeyFromFile(key.SkPath, false)
		if err != nil {
			msg := fmt.Sprintf("Could not load private key from file %s", key.SkPath)
			return errors.WrapPrefix(err, msg, 0)
		}
	}

	return nil
}

func (ls *LocalSigner) PrepareSign(keyUsage string) (pkId string, issuerNonce *big.Int, err error) {
	key, ok := ls.UsageKeys[keyUsage]
	if !ok {
		return "", nil, errors.Errorf("Specified usage key %s is not present", keyUsage)
	}

	return key.PkId, common.GenerateNonce(), nil
}

func (ls *LocalSigner) Sign(keyUsage string, credentialsAttributes [][]*big.Int, proofUs []*big.Int, holderNonce *big.Int) (isms []*gabi.IssueSignatureMessage, err error) {
	// Get specified usage key, and create signer with a non-pooling gabipool
	key, ok := ls.UsageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Specified usage key %s is not present", keyUsage)
	}

	gabiSigner := gabi.NewIssuer(key.sk, key.pk, common.BigOne)
	gabiPool := gabipool.NewRandomPool()

	// Make sure the amount of issued credentials matches the amount of commitments, then sign each credential
	credentialAmount := len(credentialsAttributes)
	if credentialAmount != len(proofUs) {
		return nil, errors.Errorf("Amount of credentials doesn't match amount of proofUs")
	}

	isms = make([]*gabi.IssueSignatureMessage, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		ism, err := gabiSigner.IssueSignature(gabiPool, proofUs[i], credentialsAttributes[i], nil, holderNonce, []int{})
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not create gabi signature", 0)
		}

		isms = append(isms, ism)
	}

	return isms, nil
}

func (ls *LocalSigner) FindIssuerPkByUsage(usage string) (pk *gabi.PublicKey, kid string, err error) {
	key, ok := ls.UsageKeys[usage]
	if !ok {
		return nil, "", errors.Errorf("Specified usage key %s is not present", usage)
	}

	return key.pk, key.PkId, nil
}

func (ls *LocalSigner) GetPrimePool() gabipool.PrimePool {
	return ls.Pool
}
