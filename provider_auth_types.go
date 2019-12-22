// +build go1.12

package oidc

import (
	"encoding/json"
	//"fmt"
	"io/ioutil"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpireIn     int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
	Scope        string `json:"scope"` // not enforced in openid
}

type tokenError struct {
	Error string `json:"error"`
}

func (t *tokenResponse) Valid() bool {
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

// TODO: clean up
func parseTokenResponse(buffer []byte) (*tokenResponse, error) {
	var t tokenResponse

	//fmt.Printf("Read token:\n%s\n", buffer)

	err := json.Unmarshal(buffer, &t)
	return &t, err
}

// TODO:
func parseOpenIdConfiguration(url string) (auth, token, issuer, jwks string, err error) {
	var ok bool

	oc := make(map[string]interface{})

	buf, err := ioutil.ReadFile(url)
	if err != nil {
		return
	}

	err = json.Unmarshal(buf, &oc)
	if err != nil {
		return
	}

	// what i need to know from the
	auth, ok = oc["authorization_endpoint"].(string)
	if !ok {
		err = ErrParse
		return
	}
	token, ok = oc["token_endpoint"].(string)
	if !ok {
		err = ErrParse
		return
	}
	issuer, ok = oc["issuer"].(string)
	if !ok {
		err = ErrParse
		return
	}
	jwks, ok = oc["jwks_uri"].(string)
	if !ok {
		err = ErrParse
		return
	}

	// this MUST be code
	//resptype, ok := oc["response_types_supported"].([]interface{}) // XXX we MUST have code inside or the provider is invalid.
	_, ok = oc["response_types_supported"].([]interface{}) // XXX we MUST have code inside or the provider is invalid.
	if !ok {
		err = ErrParse
		return
		//panic(errors.New("weird response types"))
	}

	// TODO we should be able to specify what other information we would need.
	//scopes, ok := oc["scopes_supported"] // XXX MUST have openid if not the provider is invalid.
	_, ok = oc["scopes_supported"] // XXX MUST have openid if not the provider is invalid.
	if !ok {
		err = ErrParse
		return
	}

	/*
		fmt.Printf("auth: %s / %T\n", auth, auth)
		fmt.Printf("token: %s\n", token)
		fmt.Printf("issuer: %s\n", issuer)
		fmt.Printf("scope: %s\n", scopes)
		fmt.Printf("jwks: %s / %T\n", jwks, jwks)

		fmt.Printf("resptype: %s / %T\n", resptype, resptype)

		for _, rtype := range resptype {
			fmt.Printf("r: %s / %T\n", rtype, rtype)
			// XXX TODO
			//
			//	if strings.Compare(rtype, "code") == 0 {
			//	// if we find code all good
			//		return
			//	}
			//
		}
	*/

	//fmt.Printf("PROUT: %v\n", oc)
	return
}
