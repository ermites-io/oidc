// +build go1.12

package token

import "encoding/json"

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

	//fmt.Printf("Read token:\n%s\n", buffer)

	err := json.Unmarshal(buffer, &t)
	return &t, err
}
