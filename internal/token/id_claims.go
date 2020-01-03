// +build go1.12

package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Claims
type Claims struct {
	// raw: base64
	Raw []byte

	// claims
	Sub           string `json:"sub"` // REQUIRED
	Iss           string `json:"iss"` // REQUIRED
	Aud           string `json:"aud"` // REQUIRED
	Exp           int    `json:"exp"` // REQUIRED
	Iat           int    `json:"iat"` // REQUIRED
	Email         string `json:"email"`
	Nonce         string `json:"nonce"`          // MUST
	EmailVerified bool   `json:"email_verified"` // Addition to provide some additionnal "security" and avoid abuse of oauth for login (optional)
	Azp           string `json:"azp"`            // Addition TBD
	//TODO: AtHash
}

func (h *Claims) String() string {
	return fmt.Sprintf("CLAIMS:\n\tsub: '%s'\n\tiss: '%s'\n\taud: '%s'\n\texp: '%d'\n\tiat: '%d'\n\temail: '%s'\n\tnonce: '%s'\n",
		h.Sub,
		h.Iss,
		h.Aud,
		h.Exp,
		h.Iat,
		h.Email,
		h.Nonce)
}

func (c *Claims) GetRaw() []byte {
	return c.Raw
}

// this is NOT signature check.
func (c *Claims) validate() error {
	if len(c.Sub) == 0 ||
		len(c.Iss) == 0 ||
		len(c.Aud) == 0 ||
		c.Exp == 0 ||
		c.Iat == 0 ||
		len(c.Nonce) == 0 {
		return ErrParse
	}

	return nil
}

func ParseClaims(claims64 string) (*Claims, error) {
	var c Claims

	if len(claims64) == 0 {
		return nil, ErrParse
	}

	//
	// claims
	//
	claimsJson, err := base64.RawURLEncoding.DecodeString(claims64)
	if err != nil {
		return nil, err
	}

	// unmarshal claims
	if err := json.Unmarshal(claimsJson, &c); err != nil {
		return nil, err
	}
	c.Raw = []byte(claims64)

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &c, nil
}
