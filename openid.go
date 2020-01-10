// +build go1.12

package oidc

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type OpenIDConfiguration struct {
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
	var o OpenIDConfiguration

	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	/*
		buf, err := ioutil.ReadFile(url)
		if err != nil {
			return
		}
	*/

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

	// TODO CONFIGURATION SANITY CHECKS
	// what encrypton are supported with this package etc..
	// what flow, etc..
	authz = o.AuthorizationEndpoint
	token = o.TokenEndpoint
	issuer = o.Issuer
	jwks = o.JwksURI

	return
}
