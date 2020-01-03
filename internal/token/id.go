// +build go1.12

package token

import (
	"bytes"
	"fmt"
	"strings"
)

type Id struct {
	Hdr    *Header    // Idtoken Header
	Claims *Claims    // Idtoken Claims
	Sig    *Signature // Idtoken signature
	Raw    []byte     // the raw token..
}

func (idt *Id) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n",
		idt.Hdr,
		idt.Claims,
		idt.Sig)
}

func (idt *Id) GetHeader() *Header {
	return idt.Hdr
}

func (idt *Id) GetClaims() *Claims {
	return idt.Claims
}

func (idt *Id) GetSignature() *Signature {
	return idt.Sig
}

func (idt *Id) getVerifyBlob() []byte {
	sigInput := [][]byte{idt.GetHeader().GetRaw(), idt.GetClaims().GetRaw()}
	return bytes.Join(sigInput, []byte("."))
}

func (idt *Id) GetVerifyInfo() (kid string, blob, sig []byte) {
	kid = idt.GetHeader().GetKid()
	blob = idt.getVerifyBlob()
	sig = idt.GetSignature().GetBlob()
	return
}

// FieldFunc() or Split()
// XXX TODO should be renamed to parseSafeIdToken
func Parse(token string) (*Id, error) {
	tok := strings.Split(token, ".")

	if len(token) == 0 || len(tok) != 3 {
		return nil, ErrParse
	}

	// no signature, NOPE.. invalid.
	if len(tok[0]) == 0 || len(tok[1]) == 0 || len(tok[2]) == 0 {
		return nil, ErrParse
	}

	//
	// header
	//
	hdr, err := ParseHeader(tok[0])
	if err != nil {
		return nil, err
	}
	//fmt.Printf("HEADER: %v\n", h.String())
	// TODO hdr.Validate()

	//
	// claims
	//
	claims, err := ParseClaims(tok[1])
	if err != nil {
		return nil, err
	}

	//
	// signature
	//
	sig, err := ParseSignature(tok[2])
	if err != nil {
		return nil, err
	}

	it := Id{
		Hdr:    hdr,
		Claims: claims,
		Sig:    sig,

		Raw: []byte(token),
	}
	return &it, nil
}
