package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	gobig "math/big"
	"strconv"
)

var BigOne = big.NewInt(1)
var GabiSystemParameters = gabi.DefaultSystemParameters[2048]

var ProofSerializationVersion = []byte{0x00, 0x01, 'N', 'L'}
var CredentialVersion = []byte{2}

var AttributeTypesV1 = []string{
	"isSpecimen",
	"isPaperProof",
	"testType",
	"sampleTime",
	"firstNameInitial",
	"lastNameInitial",
	"birthDay",
	"birthMonth",
}

var AttributeTypesV2 = []string{
	"isSpecimen",
	"stripType",
	"validFrom",
	"validForHours",
	"firstNameInitial",
	"lastNameInitial",
	"birthDay",
	"birthMonth",
}

type CredentialMetadataSerialization struct {
	// CredentialVersion identifies the credential version, and is always a single byte
	CredentialVersion []byte

	// IssuerPkId identifies the public key to use for verification
	IssuerPkId string
}

type ProofSerialization struct {
	Version           []byte
	UnixTimeSeconds   int64
	DisclosureChoices []bool
	C                 *gobig.Int
	A                 *gobig.Int
	EResponse         *gobig.Int
	VResponse         *gobig.Int
	AResponses        []*gobig.Int
	ADisclosed        []*gobig.Int
}

type FindIssuerPkFunc func(kid string) (pk *gabi.PublicKey, err error)

type PrepareIssueMessage struct {
	IssuerPkId       string   `json:"issuerPkId"`
	IssuerNonce      *big.Int `json:"issuerNonce"`
	CredentialAmount int      `json:"credentialAmount"`
}

type CreateCredentialMessage struct {
	IssueSignatureMessage *gabi.IssueSignatureMessage `json:"issueSignatureMessage"`
	Attributes            [][]byte                    `json:"attributes"`
}

// RandomBigInt returns a random big integer value in the range
// [0,(2^numBits)-1], inclusive.
func RandomBigInt(numBits uint) *big.Int {
	t := new(big.Int).Lsh(BigOne, numBits)

	r, err := big.RandInt(rand.Reader, t)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}

	return r
}

func GenerateNonce() *big.Int {
	return RandomBigInt(GabiSystemParameters.Lstatzk)
}

func ComputeAttributeInts(attributes [][]byte) ([]*big.Int, error) {
	// The amount of attributes including the first metadata attribute
	attributeAmount := len(attributes)
	if attributeAmount != len(AttributeTypesV2)+1 {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Compute attributes
	attrs := make([]*big.Int, attributeAmount)
	for i, val := range attributes {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes(val)

		// The last bit distinguishes empty vs. optional attributes
		// Set it, to signify that these attributes are non-optional
		attrs[i].Lsh(attrs[i], 1)
		attrs[i].Add(attrs[i], big.NewInt(1))
	}

	return attrs, nil
}

func DecodeAttributeInt(a *big.Int) []byte {
	attributeInt := new(big.Int).Set(a)

	// The last bit distinguishes empty vs. optional attributes
	if attributeInt.Bit(0) == 0 {
		// Optional attribute
		return []byte{}
	} else {
		// Empty attribute, right shift to get the actual value
		attributeInt.Rsh(attributeInt, 1)
		return attributeInt.Bytes()
	}
}

func CalculateTimeBasedChallenge(unixTimeSeconds int64) *big.Int {
	// Calculate the challenge as the sha256sum of the decimal string representation
	// of  the given unix timestamp in seconds. Cut off to appropriate amount of bits
	timeBytes := []byte(strconv.FormatInt(unixTimeSeconds, 10))
	timeHash := sha256.Sum256(timeBytes)

	challengeByteSize := GabiSystemParameters.Lstatzk / 8
	return new(big.Int).SetBytes(timeHash[:challengeByteSize])
}

func DecodeMetadataAttribute(metadataAttribute *big.Int) (credentialVersion int, issuerPkId string, err error) {
	credentialMetadata := &CredentialMetadataSerialization{}

	attributeBytes := DecodeAttributeInt(metadataAttribute)
	_, err = asn1.Unmarshal(attributeBytes, credentialMetadata)
	if err != nil {
		return 0, "", errors.WrapPrefix(err, "Could not unmarshal metadata attribute", 0)
	}

	// The credential version is defined to always be a single byte
	credentialVersion = int(credentialMetadata.CredentialVersion[0])

	return credentialVersion, credentialMetadata.IssuerPkId, nil
}

func DebugSerializableStruct(s interface{}) {
	str, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(str))
}
