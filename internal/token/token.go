// +build go1.12

package token

import (
	"encoding/json"
	"fmt"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpireIn     int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
	Scope        string `json:"scope"` // not enforced in openid
}

type ErrorMessage struct {
	Error string `json:"error"`
}

func (t *Response) String() string {
	str := fmt.Sprintf("Token Response:\n")
	str += fmt.Sprintf("\tAccess Token: '%s'\n", t.AccessToken)
	str += fmt.Sprintf("\tToken Type: '%s'\n", t.TokenType)
	str += fmt.Sprintf("\tRefresh Token: '%s'\n", t.RefreshToken)
	str += fmt.Sprintf("\tExpire in: %d\n", t.ExpireIn)
	str += fmt.Sprintf("\tId Token: '%s'\n", t.IdToken)
	str += fmt.Sprintf("\tScope: '%s'\n", t.Scope)
	return str
}

// TODO
func (t *Response) Valid() bool {
	switch {
	/*`
	case len(t.AccessToken) == 0:
		fallthrough
	*/
	case len(t.IdToken) == 0:
		fallthrough
		/*
			case len(t.ExpireIn) == 0:
				fallthrough
		*/
	case len(t.TokenType) == 0:
		return false
	}

	return true
}

func ParseResponse(buffer []byte) (*Response, error) {
	var t Response
	err := json.Unmarshal(buffer, &t)
	return &t, err
}
