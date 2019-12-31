// +build go1.12

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type Id struct {
	Hdr    Header    // Idtoken Header
	Claims Claims    // Idtoken Claims
	Sig    Signature // Idtoken signature
	Raw    []byte    // the raw token..
}

func (idt *Id) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n",
		idt.Hdr,
		idt.Claims,
		idt.Sig)
}

func (idt *Id) GetHeader() Header {
	return idt.Hdr
}

func (idt *Id) GetClaims() Claims {
	return idt.Claims
}

func (idt *Id) GetSignature() Signature {
	return idt.Sig
}

func (idt *Id) GetVerifyBlob() []byte {
	sigInput := [][]byte{idt.GetHeader().GetRaw(), idt.GetClaims().GetRaw()}
	return bytes.Join(sigInput, []byte("."))
}

func (idt *Id) GetVerifyInfo() (kid string, blob, sig []byte) {
	kid = idt.GetHeader().GetKid()
	blob = idt.GetVerifyBlob()
	sig = idt.GetSignature().GetBlob()
	return
}

// FieldFunc() or Split()
// XXX TODO should be renamed to parseSafeIdToken
func Parse(token string) (*Id, error) {
	var hdr Header
	var claims Claims
	var sig Signature

	//fmt.Printf("NEW ID TOKEN!!\n")

	//tok := strings.SplitN(idtoken, ".", 3)
	tok := strings.Split(token, ".")

	if len(token) == 0 || len(tok) != 3 {
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
	hdr.Raw = []byte(tok[0])
	//fmt.Printf("HEADER: %v\n", h.String())
	// TODO hdr.Validate()

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
	claims.Raw = []byte(tok[1])
	// TODO claims.Validate()

	//
	// signature
	//
	sigBin, err := base64.RawURLEncoding.DecodeString(tok[2])
	if err != nil {
		return nil, err
	}
	sig.Blob = sigBin
	sig.Raw = []byte(tok[2])

	it := Id{
		Hdr:    hdr,
		Claims: claims,
		Sig:    sig,

		Raw: []byte(token),
	}
	return &it, nil
}
