// +build go1.12

package token

import "fmt"

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

func (h Header) String() string {
	return fmt.Sprintf("HEADER:\n\talg: '%s'\n\tkid: '%s'\n", h.Alg, h.Kid)
}

func (h Header) GetKid() string {
	return h.Kid
}

func (h Header) GetAlg() string {
	return h.Alg
}

func (h Header) GetRaw() []byte {
	return h.Raw
}
