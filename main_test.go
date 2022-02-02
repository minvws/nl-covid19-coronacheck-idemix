package main

import (
	"fmt"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common/pool"
	"github.com/minvws/nl-covid19-coronacheck-idemix/holder"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
	"github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	gabipool "github.com/privacybydesign/gabi/pool"
)

var testKID = "testPk"
var testKeyUsage = "dynamic"

type TB interface {
	Fatal(args ...interface{})
}

func TestCredentialVersion2(t *testing.T) {
	testIssuanceDisclosureVerificationFlow(t, 2)
	testStaticIssuanceFlow(t, 2)
}

func TestCredentialVersion3(t *testing.T) {
	testIssuanceDisclosureVerificationFlow(t, 3)
	testStaticIssuanceFlow(t, 3)
}

func testIssuanceDisclosureVerificationFlow(t *testing.T, credentialVersion int) {
	credentialAmount := 3
	iss, h, holderSk, v := createIHV(t, credentialVersion, true)

	// Ask for some extra commitments
	extraCommitments := 7

	// Issuance dance
	pim, err := iss.PrepareIssue(&issuer.PrepareIssueRequestMessage{
		CredentialAmount: credentialAmount + extraCommitments,
		KeyUsage:         testKeyUsage,
	})
	if err != nil {
		t.Fatal("Could not get prepareIssueMessage:", err.Error())
	}

	credBuilders, icm, err := h.CreateCommitments(holderSk, pim)
	if err != nil {
		t.Fatal("Could not create credential commitments:", err.Error())
	}

	credentialsAttributes := buildCredentialsAttributes(credentialAmount, credentialVersion)

	im := &issuer.IssueMessage{
		PrepareIssueMessage:    pim,
		IssueCommitmentMessage: icm,
		CredentialsAttributes:  credentialsAttributes,
		CredentialVersion:      credentialVersion,
		KeyUsage:               testKeyUsage,
	}

	ccms, err := iss.Issue(im)
	if err != nil {
		t.Fatal("Could not issue credentials:", err.Error())
	}

	disclosureTime := time.Now().Unix()
	creds, err := h.CreateCredentials(credBuilders, ccms)
	if err != nil {
		t.Fatal("Could not create credentials:", err.Error())
	}

	for i := 0; i < credentialAmount; i++ {
		// Read
		readAttributes, credVersion, err := h.ReadCredential(creds[i])
		if err != nil {
			t.Fatal("Could not read credential:", err.Error())
		}

		// Check
		if credVersion != credentialVersion {
			t.Fatal("Incorrect credential version:", credVersion)
		}

		if !reflect.DeepEqual(credentialsAttributes[i], readAttributes) {
			t.Fatal("Read attributes are not the same as those issued")
		}

		// Disclose
		qr, proofIdentifier, err := h.DiscloseAllWithTimeQREncoded(holderSk, creds[i], time.Now())
		if err != nil {
			t.Fatal("Could not disclosure credential:", err.Error())
		}

		// Verify
		verifiedCred, err := v.VerifyQREncoded(qr)
		if err != nil {
			t.Fatal("Could not verify disclosed credential:", err.Error())
		}

		if !reflect.DeepEqual(credentialsAttributes[i], verifiedCred.Attributes) {
			t.Fatal("Verified attributes are not the same as those issued")
		}

		if !reflect.DeepEqual(verifiedCred.ProofIdentifier, proofIdentifier) {
			t.Fatal("Proof identifier of verified QR didn't match the one at issuance")
		}

		secondsDifference := int(math.Abs(float64(verifiedCred.DisclosureTimeSeconds - disclosureTime)))
		if secondsDifference > 5 {
			t.Fatal("Invalid verified disclosure time (or your test machine is really slow):", secondsDifference)
		}

		if verifiedCred.IssuerPkId != testKID {
			t.Fatal("Incorrect issuer public key id:", verifiedCred.IssuerPkId)
		}

		if verifiedCred.CredentialVersion != credentialVersion {
			t.Fatal("Incorrect credential version:", verifiedCred.CredentialVersion)
		}
	}
}

func testStaticIssuanceFlow(t *testing.T, credentialVersion int) {
	iss, _, _, v := createIHV(t, credentialVersion, false)

	attrs := buildCredentialsAttributes(1, credentialVersion)[0]
	attrs["isPaperProof"] = "1"
	attrs["validForHours"] = "2016"

	proofPrefixed, proofIdentifier, err := iss.IssueStatic(&issuer.StaticIssueMessage{
		CredentialAttributes: attrs,
		CredentialVersion:    credentialVersion,
		KeyUsage:             testKeyUsage,
	})
	if err != nil {
		t.Fatal("Could not issue static credential", err.Error())
	}

	verifiedCred, err := v.VerifyQREncoded(proofPrefixed)
	if err != nil {
		t.Fatal("Could not verify freshly issues static credential", err.Error())
	}

	if !reflect.DeepEqual(attrs, verifiedCred.Attributes) {
		t.Fatal("Verified attributes are not the same as those issued statically")
	}

	if !reflect.DeepEqual(verifiedCred.ProofIdentifier, proofIdentifier) {
		t.Fatal("Proof identifier of verified QR didn't match the one at issuance")
	}
}

func BenchmarkIssueStatic(b *testing.B) {
	iss, _, _, _ := createIHV(b, 3, false)
	sim := &issuer.StaticIssueMessage{
		CredentialAttributes: buildCredentialsAttributes(1, 3)[0],
		CredentialVersion:    3,
		KeyUsage:             testKeyUsage,
	}

	for i := 0; i < b.N; i++ {
		_, _, err := iss.IssueStatic(sim)
		if err != nil {
			b.Fatal("Could not issue static credential for benchmarking", err.Error())
		}
	}
}

func benchmarkIssueMultiple(b *testing.B, withPrimePool bool) {
	iss, hldr, _, _ := createIHV(b, 3, withPrimePool)

	credentialAmount := 32
	holderSk := holder.GenerateSk()

	pim, err := iss.PrepareIssue(&issuer.PrepareIssueRequestMessage{
		KeyUsage:         testKeyUsage,
		CredentialAmount: credentialAmount,
	})
	if err != nil {
		b.Fatal("Could not create prepare issue message", err.Error())
	}

	_, icm, err := hldr.CreateCommitments(holderSk, pim)
	if err != nil {
		b.Fatal("Could not create commitments", err.Error())
	}

	im := &issuer.IssueMessage{
		PrepareIssueMessage:    pim,
		IssueCommitmentMessage: icm,
		CredentialsAttributes:  buildCredentialsAttributes(32, 3),
		CredentialVersion:      3,
		KeyUsage:               testKeyUsage,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := iss.Issue(im)
		if err != nil {
			b.Fatal("Could not issue credentials for benchmarking", err.Error())
		}
	}
}

func BenchmarkIssueMultiple(b *testing.B) {
	benchmarkIssueMultiple(b, false)
}

func BenchmarkIssueMemoryPool(b *testing.B) {
	benchmarkIssueMultiple(b, true)
}

func buildCredentialsAttributes(credentialAmount int, credentialVersion int) []map[string]string {
	cas := make([]map[string]string, 0, credentialAmount)

	for i := 0; i < credentialAmount; i++ {
		validFrom := time.Now().Round(time.Hour).AddDate(0, 0, i).UTC().Unix()

		ca := map[string]string{
			"isSpecimen":       "0",
			"isPaperProof":     "0",
			"validFrom":        strconv.FormatInt(validFrom, 10),
			"validForHours":    "24",
			"firstNameInitial": "A",
			"lastNameInitial":  "R",
			"birthDay":         "20",
			"birthMonth":       "10",
		}

		if credentialVersion == 3 {
			ca["category"] = "2G"
		}

		cas = append(cas, ca)
	}

	return cas
}

func createIHV(t TB, credentialVersion int, withPrimePool bool) (*issuer.Issuer, *holder.Holder, *big.Int, *verifier.Verifier) {
	iss := createIssuer(t, withPrimePool)

	pk, _, _ := iss.Signer.FindIssuerPk(&localsigner.KeySpecification{
		KeyUsage: testKeyUsage,
	})
	h, holderSk := createHolder(pk, credentialVersion)
	v := createVerifier(pk)

	return iss, h, holderSk, v
}

func createIssuer(t TB, withPrimePool bool) *issuer.Issuer {
	var primePool gabipool.PrimePool
	if withPrimePool {
		fmt.Println("Prefilling memory pool...")
		primePool = pool.NewMemoryPool(1000, 10, 100, 644, 119, -1)
		for !primePool.(*pool.MemoryPool).IsFull() {
			time.Sleep(1 * time.Second)
		}
		fmt.Println("Memory pool warmup completed")
	} else {
		primePool = gabipool.NewRandomPool()
	}

	pks := []*localsigner.Key{
		{
			KeyUsage:      testKeyUsage,
			KeyIdentifier: testKID,
			PkPath:        "./testdata/pk.xml",
			SkPath:        "./testdata/sk.xml",
		},
	}
	ls, err := localsigner.New(pks, primePool)
	if err != nil {
		t.Fatal("Could not create signer:", err.Error())
	}

	return issuer.New(ls)
}

func createHolder(pk *gabi.PublicKey, credentialVersion int) (*holder.Holder, *big.Int) {
	holderSk := holder.GenerateSk()
	findIssuerPk := buildFindIssuerPkFunc(testKID, pk)
	return holder.New(findIssuerPk, credentialVersion), holderSk
}

func createVerifier(pk *gabi.PublicKey) *verifier.Verifier {
	findIssuerPk := buildFindIssuerPkFunc(testKID, pk)
	return verifier.New(findIssuerPk)
}

func buildFindIssuerPkFunc(kid string, pk *gabi.PublicKey) common.FindIssuerPkFunc {
	return func(askedKID string) (*gabi.PublicKey, error) {
		if askedKID != kid {
			return nil, errors.Errorf("Invalid kid passed test function")
		}

		return pk, nil
	}
}
