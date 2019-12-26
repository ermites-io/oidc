// +build go1.12

package token

import "fmt"

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
}

func (h Claims) String() string {
	return fmt.Sprintf("CLAIMS:\n\tsub: '%s'\n\tiss: '%s'\n\taud: '%s'\n\texp: '%d'\n\tiat: '%d'\n\temail: '%s'\n\tnonce: '%s'\n",
		h.Sub,
		h.Iss,
		h.Aud,
		h.Exp,
		h.Iat,
		h.Email,
		h.Nonce)
}

func (c Claims) GetRaw() []byte {
	return c.Raw
}
