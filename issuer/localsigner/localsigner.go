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
	KeyIdentifier string `mapstructure:"key-identifier"`
	PkPath        string `mapstructure:"public-key-path"`
	SkPath        string `mapstructure:"private-key-path"`

	// DEPRECATED: This field is deprecated and should be removed when callers have been migrated
	KeyUsage string `mapstructure:"key-usage"`

	pk *gabi.PublicKey
	sk *gabi.PrivateKey
}

// DEPRECATED: This struct is temporary and should be removed when callers have been migrated
type KeySpecification struct {
	KeyIdentifier string

	// DEPRECATED: Deprecated field in temporary structure
	KeyUsage string
}

type LocalSigner struct {
	primePool        gabipool.PrimePool
	keysByIdentifier map[string]*Key

	// DEPRECATED: This field is deprecated and should be removed when callers have been migrated
	keysByUsage map[string]*Key
}

func New(keys []*Key, pool gabipool.PrimePool) (*LocalSigner, error) {
	ls := &LocalSigner{
		primePool:        pool,
		keysByIdentifier: map[string]*Key{},
		keysByUsage:      map[string]*Key{},
	}

	err := ls.loadKeys(keys)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not load local signer keys", 0)
	}

	return ls, nil
}

func (ls *LocalSigner) loadKeys(keys []*Key) error {
	var err error
	for _, key := range keys {
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

		// Determine if this a key by identifier and/or by usage
		if key.KeyIdentifier == "" && key.KeyUsage == "" {
			return errors.Errorf("Supplied key should have either an identifier or a (deprecated) usage")
		}

		if key.KeyIdentifier != "" {
			ls.keysByIdentifier[key.KeyIdentifier] = key
		}

		if key.KeyUsage != "" {
			ls.keysByUsage[key.KeyUsage] = key
		}
	}

	return nil
}

func (ls *LocalSigner) PrepareSign(ks *KeySpecification) (pkId string, issuerNonce *big.Int, err error) {
	key, err := ls.findKeyByIdentifierOrUsage(ks)
	if err != nil {
		return "", nil, err
	}

	return key.KeyIdentifier, common.GenerateNonce(), nil
}

func (ls *LocalSigner) Sign(ks *KeySpecification, credentialsAttributes [][]*big.Int, proofUs []*big.Int, holderNonce *big.Int) (isms []*gabi.IssueSignatureMessage, err error) {
	key, err := ls.findKeyByIdentifierOrUsage(ks)
	if err != nil {
		return nil, err
	}

	gabiSigner := gabi.NewIssuer(key.sk, key.pk, common.BigOne)

	// Make sure the amount of issued credentials matches the amount of commitments, then sign each credential
	credentialAmount := len(credentialsAttributes)
	if credentialAmount != len(proofUs) {
		return nil, errors.Errorf("Amount of credentials doesn't match amount of proofUs")
	}

	isms = make([]*gabi.IssueSignatureMessage, 0, credentialAmount)
	for i := 0; i < credentialAmount; i++ {
		ism, err := gabiSigner.IssueSignature(ls.primePool, proofUs[i], credentialsAttributes[i], nil, holderNonce, []int{})
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not create gabi signature", 0)
		}

		isms = append(isms, ism)
	}

	return isms, nil
}

func (ls *LocalSigner) FindIssuerPk(ks *KeySpecification) (pk *gabi.PublicKey, kid string, err error) {
	key, err := ls.findKeyByIdentifierOrUsage(ks)
	if err != nil {
		return nil, "", err
	}

	return key.pk, key.KeyIdentifier, nil
}

func (ls *LocalSigner) GetPrimePool() gabipool.PrimePool {
	return ls.primePool
}

func (ls *LocalSigner) findKeyByIdentifierOrUsage(ks *KeySpecification) (*Key, error) {
	if ks.KeyIdentifier != "" {
		key, ok := ls.keysByIdentifier[ks.KeyIdentifier]
		if !ok {
			return nil, errors.Errorf("Specified key for identifier %s is not present", ks.KeyIdentifier)
		}

		return key, nil
	}

	if ks.KeyUsage != "" {
		key, ok := ls.keysByUsage[ks.KeyUsage]
		if !ok {
			return nil, errors.Errorf("Specified key for usage %s is not present", ks.KeyUsage)
		}

		return key, nil
	}

	return nil, errors.Errorf("No key identifier or usage was specified")
}
