// +build  go1.12

package token

import (
	"encoding/base64"
	"fmt"
)

// signature
type Signature struct {
	// raw: base64
	Raw []byte

	// debase64 signature
	Blob []byte
}

func (s *Signature) String() string {
	return fmt.Sprintf("SIG: '%s'\n", s.Raw)
}

func (s *Signature) GetBlob() []byte {
	return s.Blob
}

func ParseSignature(sig64 string) (*Signature, error) {
	var s Signature

	if len(sig64) == 0 {
		return nil, ErrParse
	}

	//
	// signature
	//
	sigBin, err := base64.RawURLEncoding.DecodeString(sig64)
	if err != nil {
		return nil, err
	}
	s.Blob = sigBin
	s.Raw = []byte(sig64)

	return &s, nil
}
