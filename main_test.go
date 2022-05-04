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
	testIssuanceDisclosureVerificationFlow(t, 2, holder.CATEGORY_DISCLOSED_V2_SERIALIZATION)
	testIssuanceDisclosureVerificationFlow(t, 2, holder.CATEGORY_DISCLOSED_V3_SERIALIZATION)
	testStaticIssuanceFlow(t, 2)
}

func TestCredentialVersion3(t *testing.T) {
	testIssuanceDisclosureVerificationFlow(t, 3, holder.CATEGORY_DISCLOSED_V2_SERIALIZATION)
	testIssuanceDisclosureVerificationFlow(t, 3, holder.CATEGORY_DISCLOSED_V3_SERIALIZATION)
	testStaticIssuanceFlow(t, 3)
}

func TestHideCategory(t *testing.T) {
	testIssuanceDisclosureVerificationFlow(t, 3, holder.CATEGORY_HIDDEN)
}

func testIssuanceDisclosureVerificationFlow(t *testing.T, credentialVersion int, categoryMode int) {
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
		qr, proofIdentifier, err := h.DiscloseWithTimeQREncoded(holderSk, creds[i], categoryMode, time.Now())
		if err != nil {
			t.Fatal("Could not disclosure credential:", err.Error())
		}

		// Verify
		verifiedCred, err := v.VerifyQREncoded(qr)
		if err != nil {
			t.Fatal("Could not verify disclosed credential:", err.Error())
		}

		if categoryMode == holder.CATEGORY_HIDDEN {
			delete(credentialsAttributes[i], "category")
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

func TestPreviousDisclosureImplementation(t *testing.T) {
	qrs := []string{
		"NL2:SJQZYV54X%7B LY2JZE7O962F:MUE*0/*D8SBS4$2:+ Y$ISBID/HE*$ EM3/VFLO%+TRG8598%0T0H16HA5+S:- 6L/Q+VKI5P-Y%CO/QPX4+2FX8Q9XW88KEHJB*JD/SAGWW$S8Q7N:3Q7JPU/I6-QQ+GGG3J5N$8-8Q* S430CV8LHYU6VUZQ4C*5WGGAMCV P.$I-MT4DIMM-ZZ+F.ABQ63.ZT%S8BXB.MF9DEZVCV:8F/SC0LIS.OG5-+5+FGAC5BDT%FE T0RG.3NM5-.65Y%+CAIGUBC-PDMGWW/W-K8O4BT02BDC8T$2 O$0M681+P8Z:W02R-I-Q-TAQ%-$RM2B%QR5-3Y9L$$1G0+BTD782RCWFRY107BEW1$-314QRMG2LSDSQTU--3OC*64VLNZ H63Z-BZ :NQRREBE1$OUSF-Q2D/O.MT+KRM3XV+5*V6$GH3I//WH3XP*X3WZ /EV--HJ   3J0ORVP6PAA9113YJ-YG:7EWR$06IFHG$MH82-T55.BE9LG-7XUX0C1VY2N0ABX:OIW8+2B.4Y 09:MC3A03AH3URRO3R+5Z04BVTES9Y$CY2*Z18GO+4VJRFE61D8LOUB/FO0T071LW O*9J  $$N$Q$.2R1Q-G0R. T84WA%-D2RO%9UXFSX0B:UA1QJ5$%7RBZQ9V/N0$K2:/O3KGFKKMQCEUU8S/TX-%OHUJD1WT$BSZD604L8MW77KWJZ8IUE:$NIYBEMIJN0BO/I32-NU4LSSANHKJXL0KMZCE%4W5LNL/RCKORW-7WZ%ITUZ+TDS++AR4TP99L5PU*H30KB7O5LD%T8K1V1JBSEAQO2F0R0:YYULFOP 7CP4V8KZ/1S/.Y%XR9E4VM3ABH7-$:$%R GX77I6Y+LBD6.W/0KM/YX$2+K 5JRRMF*K EF1E1N3QHAV76JPHETW1+E51HB6.L.7N0HTRXEGNTGP$Z6:G$JMBUEW8*3FMOA26LK$2KU$HC0PJ5VU67/1/DDV:DP$$7KF%1/ M-1UDU6P77OUPD CZ*YOG+TZ CH.GFRPR%NZS.H9DXQHRSFM+1%1-1R%RU*A6*CZ3E%LTE1K/KXERL1CHF43T+61K.0 1$C-F-9Z%:1H:.IA%Q+4D6U.$1:J3F$I/HTDE$F/FU2UP9IU+ +HMKGZCR:WRDD0YBVP8TWI.T $YZ4OD0%O/N+SY:Q*JNIO9MSOZM0ZSQ$S/*CS$B1-I24H9%43*QNM8$H5CO8+Y24..RQM60-K6U51*H/ SNM8/0PKD4N.Z 8TVLA6BZ*KXJ.*/1 PW1X0:4G/9X43",
		"NL2:SJQZYV543NID 4.0ZWAT+6SJ*3U97HV1EKJ189M V%V6RP:9H1G9N*UPK7TZK9ZCP7%Q%2SW7U4VN:A%ZAR%E3$QCU:8A./4B49N9.J4-A 94HH:9B$NQDA38GN50M67DP08Q2$6CU2QXDY$3ER2QWRC%$N9-$69J1GX0A395ANSFBM32PKY6UL4*BH$5K KI4J0M%Z*+4MZ%UGTW8ED-YVEP0DISL/2BM-8XC5R0VIEG40HE5W+. ZAEU035F06%0C+ $H0*-M+CPP*:B9KT%T:HZWM 586W+CUGTCL:2U2X*I-MFK/UM*$Y*KW6FL33U7/Q6.V3SBO85P928TDKRN0ZMTX-7S*9.0/OT2ZT8-WCGT2TD0:0B9OIWTNL2SDM+N4LT3D SLV7AT4ZJBBD:KO7+NG%JG0APZ7.7:F-/%XLUXK.HKHTE6+-Z%SYNUVQMIRW1+KNEO-H%9QR5512BHKQUQS5ABQTQS3LK1NN0ESB-+W0PYFB3QRIO/9HXIVCRZIKW.DEUR+KB$K0$KEX .RT89NSA+SV5TQEU H713Z77+XCQUCF4EUTFD%95. LFYENXLZC+ QRDW39TO. DW/3*.4PNV5%%6MZKKOYSIT27O+.J*%HHXCV/P5SRTN:%S5WVRIV*/YN$ LA.DL/1.NQP96S:X:CZR.-BEFONMNL:$83CU-P3LOS8WPKVMX5CCGWY-PS0US+TKAA6G3NOH+37NBC%K1$9L9-EY5TEOF+BGLWKBNGANE9E7CE%AZ2 X4P+0*G %D65+A046 L19LDI5TZORG%6P61-44+5L53$SA5:UQ$8OCMQXB8K7PI2:V1L56JIY7VUN5CRR3TWXSR68C2 7RH$JR3R0LT6T6SE30RR%XFNZ/CN:LACE2/MX9-SZV1A-1+*IH-Q3BX W8SHF%92NY/Z:EBVD%UFS*%:0-Q2*NE-W/8KY4R9270ETFJJQH:3:YF%7M/:5$101WOCBMJV7OBF- HNURQM%QHM3KP2:*7QL*4M-NF 1LPDJFXGR343BLWC%/J7A*7*JCDR1S8H8RW9XJRWK*N5RT:.V4RNRDBD29V5RM.F$RQ+H/.4O%UNAN.MXRHJ299$6YEJZS6F7O:QAR3B9HH%DE7:%.:-NTZIBBV4$K$D 41-2I%B%+BP8UGV65J6Z7.FGQININYEX6LGOP+AYV86KPPPY$JPQXABJ.7*Q6ZGW0$1B1R*MO1TM$U8BANME:UT47GLMKF2BYE7G4QJE*RVQUR:%V6WDZM5Z*U./ZRZANZ.S+X:$I5Y87WYLC0:8/3TL++52EC0664DF.3K",
		"NL2:AP:TB89KZ1IEUF*M7ZCC3:S4.P*1AJ/2VYGSOF.DFO7$K3R.SN-5T-9NBOT V-W+.UPR6OTB:HF18PDS*CHBOKNKYXGC.CSDWOQ1KZ+U%SL*SV/I%/L I$GY%Z*/U26S2QFLTLML$BP34*KL:X%+V0-$9PQ8N919V:ZOB 8DN/*$71-LK.CVZK4K42G38OZJ*K82.+BU8M.QUEUD4 Y1 :ESZ0PCG6UKQ8B4CYWGEC2EC%58H443Y9/L2ZG52$XJ2D+$32MYNI5+Z5*NMHF5D+3OLR$77M%8GM%/P5HID5GPV%AGSLO2BN+*HIW42/HSXT82/:1W0BU+IZ6Y3I%S+H8DB9.CB80B.FEHF-ZE0-3*A6SF.$ORGWV%WFYG$B.5GP YLIQCLH:H*%SPL$W%GM73BX9AUU.NXWC5/$K9HRSDA71RY+8D866CDO63L*8%WV:NUDP-Z50WRYC 1B5 :Z49$+O*BMRXY 7:G+SXQVXV/TXN.::9-A9PPUY4I-:-GC1GB5EXX61*SN9SE*G2/LRTZ:+I1:XU%$DQC 6FWXUVA5AFDVLLUQBBT8B6LRGAB:R-2ZA*4/S8JWI7SD-949.LLIV226IMD/GZGU0M9AA/D9TR218GI*R56TF8W46SK0CZ9:K/SZNE16   IFYX74/5-1U0.MMX6Y3BW*%MISTIA5DF89BGTTRHHN3Z89.69DSHNS 5XMNHLUAPCA9C.UEU83O2AS8TXOE+J8+B*3B6+NT5XAH$OEQXVNYEJ.$AU:GNE1FXZFECSD17MM*PL$DT1RNEL4MN-R$KK47%KN*SE%T57Y85$ATZUP90-72RV3SJH3DB768Z$2QM4W GQ3M/E*8RNM9L*5EH+-:AY4XWJA9X8SALJ*HPL:/4*$K54M3$Q$+5AEJ66$XGT9 8HJFGES7$:DLK56FR*YZ:++%+N-1Y24V+D3%BO1*7AE%5NE$JI:+G1J9PXN-NWL *D1W8NSMFRWQGL+:-UQOPSFYRS1309X$92EZD6:45OVXGE C.N26J/BJFRV6/6HANIBGRCBZZ3A01EB.C6F%E+7D*S+%6VH%W2*7-:-V6SJ*4:82UFLI:2*PBIEJ1MEQ+TB2WCL4OW4BI3*K%OWG6-L1ZFU.ET6W4D2%1QWVVG5RX:R9/E1/F$DF5HU6QS5HX2C7$N7Q4/+J/./BPJIH-*O*IM%K1EJ+G%/HGBI9C9/IPU4:XX*R:::6B%MTX$JUXBA$L:V1VK005 BU0282J:Q$JYJKHW%%Q-I5NMLPF2 OPVT-IDBE0MICYQ3JSPDNP4UVA0A$ZS48O*$0JJ51A/-G6CM",
		"NL2:1%U7Z06I.ZWNB32%8AVLTR$34P:PO0B7X74YQ 9V$LG6OZGIQOW84%DL8$RZ 7LR1YQOC:V*93IY28QTOFPIN93AF X9X P82G8GU%3O-%ZQLL5T7N%-ZXNWHQQA/-**%SJC7GT-J 2TO$W+.88--ICAZ3TOVF1BICN8R/1*PF+F$HA*IH7V*Q1S/UN84JCVXS1AHRVKVJNOSM%59BQB2FC-AZV91LOB:UQH0/5+83AKQO5MJVB9CEQNYP9HOR-*+VPPSKG9DPMZ:-SR.+:142D6VH9ONH2R/LV73RE:93T4I3T%2BFHQG:D8%0+:-EC- V8W3. W/SYMN5-Q+Q$B4G.59ZPA:ZRYWGJN+47D+P2J%2ZE5E*TQ9*9L5LVTK-.SN6MVXANLPR9RLG2W1VF:2J8JH 1DN2 N%83IEU:: $EU E*5FI*1CQ1 3/QYKDJSL-UAQDUVR2%DL1.SB67GAM1XQL1JTLLZXAO-J9CYEANN2-Y2 7F*P OKX$*O38ROWDN% O DQBD%O/RVE+O$F4UOO51RC*2RQQGPO/4:$NBIMNTH*XYSBE 0+*$V HHG6Y39GCUAJ4FQWA57ELNH0YBXULYY8FO//HY0*:PIK:CBNO/7AGJ/ +U.VH1DNY3S6HUB6F5TR%P7/*00*FRGIN1AJ%:%LLQYRGJ$+X12EDIBUS61X.B:$:3MR.H$S50Q2Y-AJ*:7*BP-LWC-KO2AY9VJH:-/IC$ECEYE7:D:QY/FGXVFX-:/4T.A206.%5UQJV$$E:K* XI6SJS 0+%RM5WD%Q2KWH6QTZL3M22N3SBVC3Z51HMV+7M$M0U.12I72YLB%W4DKUWNK.%PU8RYJ2RHPL:93-A3$TX/.Q%KZHC*Z+5PC1$+60/PR842LEU-C/D1MC+9019S* CKD68SK/3MUF$.NNF6WLAT%5HXSFKF7Y*6+$H3YT/4K*S.0I+MIM 5IM:6S:H0NUPWTS.NQK95:KBYHRZ-:YS%/J3LDR.7LF4-B03IXI$I3F$ZIWFKDGHZWGXM0UWV1TH7 MTK7IX$RJ/8S$R/P$G6P6SBU93E75IIG3+/QA/1J/AJ+4G+8F3S*UBL:ZXQ-:HPX94WUO0 79$EUVLY3+UPV2W:/7..89KT0JO0H/GGE C3TKSUZEL4XPNXYET2.DT4N4S A*6WO0471YWSE$IQ:8BZ3X$TGI1+.%OWHSF 9%D7MSTS0X2JL0OVJJ1*N3L8O.BX:Q2G:TN1DHX:7UA2%KM/44E8B6BLW+-.D921BFZ9RB61%Y%C+T:PAUQFWD:F7SQBZBB Y5A%UZ5TG6C6*15ZB9KP",
	}

	_, _, _, v := createIHV(t, -1, false)
	for i, qr := range qrs {
		_, err := v.VerifyQREncoded([]byte(qr))
		if err != nil {
			t.Fatalf("Couldn't verify previous disclosure QR #%d\n", i)
		}
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
			ca["category"] = "1"
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
		primePool = pool.NewMemoryPool(101, 10, 100, 644, 119, -1)
		for !primePool.(*pool.MemoryPool).IsFull() {
			time.Sleep(100 * time.Millisecond)
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
