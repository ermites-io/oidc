// +build go1.12

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

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
type ih struct {
	// raw: base64
	raw []byte

	// header
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

func (h ih) String() string {
	return fmt.Sprintf("HEADER:\n\talg: '%s'\n\tkid: '%s'\n", h.Alg, h.Kid)
}

// Claims
type ic struct {
	// raw: base64
	raw []byte

	// claims
	Sub           string `json:"sub"`
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Exp           int    `json:"exp"`
	Iat           int    `json:"iat"`
	Email         string `json:"email"`
	Nonce         string `json:"nonce"`
	EmailVerified bool   `json:"email_verified"` // Addition to provide some additionnal "security" and avoid abuse of oauth for login (optional)
	Azp           string `json:"azp"`            // Addition TBD
}

func (h ic) String() string {
	return fmt.Sprintf("CLAIMS:\n\tsub: '%s'\n\tiss: '%s'\n\taud: '%s'\n\texp: '%d'\n\tiat: '%d'\n\temail: '%s'\n\tnonce: '%s'\n",
		h.Sub,
		h.Iss,
		h.Aud,
		h.Exp,
		h.Iat,
		h.Email,
		h.Nonce)
}

// signature
type is struct {
	// raw: base64
	raw []byte

	// debase64 signature
	blob []byte
}

func (s is) String() string {
	return fmt.Sprintf("SIG: '%s'\n", s.raw)
}

type IdToken struct {
	hdr    ih     // Idtoken Header
	claims ic     // Idtoken Claims
	sig    is     // Idtoken signature
	raw    string // the raw token..
}

func (idt *IdToken) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n",
		idt.hdr,
		idt.claims,
		idt.sig)
}

// FieldFunc() or Split()
// XXX TODO should be renamed to parseSafeIdToken
func newIdToken(idtoken string) (*IdToken, error) {
	var hdr ih
	var claims ic
	var sig is

	//fmt.Printf("NEW ID TOKEN!!\n")

	//tok := strings.SplitN(idtoken, ".", 3)
	tok := strings.Split(idtoken, ".")

	if len(tok) != 3 {
		//return nil, errors.New("invalid token for us")
		return nil, ErrParse
	}

	// no signature, NOPE.. invalid.
	if len(tok[0]) == 0 || len(tok[1]) == 0 || len(tok[2]) == 0 {
		//return nil, errors.New("invalid token for us")
		return nil, ErrParse
	}

	//
	// header
	//
	hdrJson, err := base64.RawURLEncoding.DecodeString(tok[0])
	if err != nil {
		return nil, err
	}
	// unmarshal header
	err = json.Unmarshal(hdrJson, &hdr)
	if err != nil {
		return nil, err
	}
	hdr.raw = []byte(tok[0])
	//fmt.Printf("HEADER: %v\n", h.String())

	//
	// claims
	//
	claimsJson, err := base64.RawURLEncoding.DecodeString(tok[1])
	if err != nil {
		return nil, err
	}

	// unmarshal claims
	err = json.Unmarshal(claimsJson, &claims)
	if err != nil {
		return nil, err
	}
	claims.raw = []byte(tok[1])

	//
	// signature
	//
	sigBin, err := base64.RawURLEncoding.DecodeString(tok[2])
	if err != nil {
		return nil, err
	}
	sig.blob = sigBin
	sig.raw = []byte(tok[2])

	it := IdToken{
		hdr:    hdr,
		claims: claims,
		sig:    sig,
	}
	return &it, nil
}
