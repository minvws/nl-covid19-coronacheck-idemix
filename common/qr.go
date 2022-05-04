package common

import "github.com/go-errors/errors"

func HasNLPrefix(bts []byte) bool {
	_, _, err := ExtractProofVersion(bts)
	return err == nil
}

func ExtractProofVersion(proofPrefixed []byte) (proofVersionByte byte, proofBase45 []byte, err error) {
	if len(proofPrefixed) < 4 {
		return 0x00, nil, errors.Errorf("Could not process abnormally short QR")
	}

	if proofPrefixed[0] != 'N' || proofPrefixed[1] != 'L' || proofPrefixed[3] != ':' {
		return 0x00, nil, errors.Errorf("QR is not prefixed as an NL entry proof")
	}

	proofVersionByte = proofPrefixed[2]
	if !((proofVersionByte >= '0' && proofVersionByte <= '9') || (proofVersionByte >= 'A' && proofVersionByte <= 'Z')) {
		return 0x00, nil, errors.Errorf("QR has invalid context id byte")
	}

	return proofVersionByte, proofPrefixed[4:], nil
}
