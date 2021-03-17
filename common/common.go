package common

import (
	"crypto/rand"
	"crypto/sha256"
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
var CredentialVersion = []byte{1}

var AttributeTypes = []string{
	"isSpecimen",
	"isPaperProof",
	"testType",
	"sampleTime",
	"firstNameInitial",
	"lastNameInitial",
	"birthDay",
	"birthMonth",
}

type CredentialMetadataSerialization struct {
	CredentialVersion []byte
	IssuerPkId        string
}

type NonceSerialization struct {
	Nonce      *gobig.Int
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

type CreateCredentialMessage struct {
	IssueSignatureMessage *gabi.IssueSignatureMessage `json:"ism"`
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
	if attributeAmount != len(AttributeTypes)+1 {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Compute attributes
	attrs := make([]*big.Int, attributeAmount)
	for i, val := range attributes {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes(val)

		// Let the last bit distinguish empty vs. optional attributes
		attrs[i].Lsh(attrs[i], 1)             // attr <<= 1
		attrs[i].Add(attrs[i], big.NewInt(1)) // attr += 1
	}

	return attrs, nil
}

func DecodeAttributeInt(a *big.Int) []byte {
	attributeInt := new(big.Int).Set(a)

	if attributeInt.Bit(0) == 0 {
		// TODO: Decide if and how to support optional attributes
		return []byte{}
	} else {
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

func DebugSerializableStruct(s interface{}) {
	str, _ := json.Marshal(s)
	fmt.Println(string(str))
}
