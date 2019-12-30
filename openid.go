// +build go1.12

package oidc

import (
	"encoding/json"
	"io/ioutil"
)

type OpenIDConfiguration struct {
	// REQUIRED
	Issuer                           string   `json:"issuer"`                                // REQUIRED
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`                // REQUIRED
	TokenEndpoint                    string   `json:"token_endpoint"`                        // REQUIRED
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`                     // REQUIRED
	JwksURI                          string   `json:"jwks_uri"`                              // REQUIRED
	ResponseTypeSupported            []string `json:"response_types_supported"`              // REQUIRED
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // REQUIRED
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // REQUIRED
	RegistrationEndpoint             string   `json:"registration_endpoint"`                 // RECOMMENDED ONLY
	ScopeSupported                   []string `json:"scope_supported"`                       // RECOMMENDED ONLY
	ClaimsSupported                  []string `json:"claims_supported"`                      // RECOMMENDED ONLY
}

// TODO:
func parseOpenIDConfiguration(url string) (authz, token, issuer, jwks string, err error) {
	//var ok bool

	//oc := make(map[string]interface{})
	var o OpenIDConfiguration

	buf, err := ioutil.ReadFile(url)
	if err != nil {
		return
	}

	//err = json.Unmarshal(buf, &oc)
	err = json.Unmarshal(buf, &o)
	if err != nil {
		return
	}

	if len(o.Issuer) == 0 ||
		len(o.AuthorizationEndpoint) == 0 ||
		len(o.TokenEndpoint) == 0 ||
		len(o.UserinfoEndpoint) == 0 ||
		len(o.JwksURI) == 0 ||
		len(o.ResponseTypeSupported) == 0 ||
		len(o.SubjectTypesSupported) == 0 ||
		len(o.IdTokenSigningAlgValuesSupported) == 0 {
		err = ErrParse
		return
	}

	authz = o.AuthorizationEndpoint
	token = o.TokenEndpoint
	issuer = o.Issuer
	jwks = o.JwksURI

	return
	// what i need to know from the
	/*
		authz, ok = oc["authorization_endpoint"].(string)
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
	*/

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
	//return
}
