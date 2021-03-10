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

var AttributeTypes = []string{
	"testType",
	"sampleTime",
	"firstNameInitial",
	"lastNameInitial",
	"birthDay",
	"birthMonth",
}

type ProofSerialization struct {
	UnixTimeSeconds   int64
	DisclosureChoices []bool
	C                 *gobig.Int
	A                 *gobig.Int
	EResponse         *gobig.Int
	VResponse         *gobig.Int
	AResponses        []*gobig.Int
	ADisclosed        []*gobig.Int
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

func ComputeAttributes(attributes map[string]string) ([]*big.Int, error) {
	attributeAmount := len(attributes)
	if attributeAmount != len(AttributeTypes) {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Map map to list of attributes in the correct order
	attributeValues := make([]string, attributeAmount)
	for i := 0; i < attributeAmount; i++ {
		attributeType := AttributeTypes[i]

		v, ok := attributes[attributeType]
		if !ok {
			return nil, errors.Errorf("Required attribute %s was not supplied", attributeType)
		}

		attributeValues[i] = v
	}

	// Compute attributes
	attrs := make([]*big.Int, len(attributeValues))
	for i, val := range attributeValues {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes([]byte(val))

		// Let the last bit distinguish empty vs. optional attributes
		attrs[i].Lsh(attrs[i], 1)             // attr <<= 1
		attrs[i].Add(attrs[i], big.NewInt(1)) // attr += 1
	}

	return attrs, nil
}

func DecodeAttributeInt(a *big.Int) string {
	attributeInt := new(big.Int).Set(a)

	if attributeInt.Bit(0) == 0 {
		// TODO: Decide if and how to support optional attributes
		return ""
	} else {
		attributeInt.Rsh(attributeInt, 1)
		return string(attributeInt.Bytes())
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
