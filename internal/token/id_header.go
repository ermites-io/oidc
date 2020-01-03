// +build go1.12

package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var supportedAlg = map[string]bool{
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
}

// alg
// RS256 == RSASSA-PKCS1-v1_5 + SHA256
// RS384 == RSASSA-PKCS1-v1_5 + SHA384
// RS512 == RSASSA-PKCS1-v1_5 + SHA512
// ES256 == ECDSA P-256 + SHA256
// ES384 == ECDSA P-384 + SHA384
// ES512 == ECDSA P-521 + SHA512
// PS256
// PS384
// PS512
// none => EXIT |
//
// unsecured JWS == len sig == 0
type Header struct {
	// raw: base64
	Raw []byte

	// header
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

func (h *Header) String() string {
	return fmt.Sprintf("HEADER:\n\talg: '%s'\n\tkid: '%s'\n", h.Alg, h.Kid)
}

func (h *Header) GetKid() string {
	return h.Kid
}

func (h *Header) GetAlg() string {
	return h.Alg
}

func (h *Header) GetRaw() []byte {
	return h.Raw
}

func (h *Header) validate() error {
	if len(h.Kid) == 0 || len(h.Alg) == 0 {
		return ErrParse
	}

	_, ok := supportedAlg[h.Alg]
	if !ok {
		return ErrParse
	}

	return nil
}

func ParseHeader(header64 string) (*Header, error) {
	var h Header

	if len(header64) == 0 {
		return nil, ErrParse
	}
	//
	// header
	//
	hdrJson, err := base64.RawURLEncoding.DecodeString(header64)
	if err != nil {
		return nil, err
	}
	// unmarshal header
	err = json.Unmarshal(hdrJson, &h)
	if err != nil {
		return nil, err
	}

	if h.validate() != nil {
		return nil, err
	}

	h.Raw = []byte(header64)
	return &h, nil
}
