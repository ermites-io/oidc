package oidc

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/ermites-io/oidc/internal/token"
)

func (p *Provider) buildUrlAuth(responseType, scope, nonce, state string) (string, error) {
	var nilstr string

	// parse url defined
	u, err := url.ParseRequestURI(p.urlAuth)
	if err != nil {
		return nilstr, err
	}

	// build query.
	v := u.Query()

	//v := url.Values{}
	v.Set("client_id", p.clientId)
	v.Set("response_type", responseType)
	v.Set("scope", scope)
	v.Set("nonce", nonce)
	v.Set("state", state)
	v.Set("redirect_uri", p.clientUrlRedirect)

	u.RawQuery = v.Encode()
	return u.String(), nil
}

func (p *Provider) buildFormToken(code string) url.Values {
	// grantType for authorization_code flows
	// code MUST be part of the grand types
	grantType := "authorization_code"

	v := url.Values{}
	v.Set("grant_type", grantType)

	// common
	v.Set("code", code)
	v.Set("client_id", p.clientId)
	v.Set("client_secret", p.clientSecret)
	v.Set("redirect_uri", p.clientUrlRedirect)
	return v
}

func (p *Provider) buildFormTokenOauth(code, state string) url.Values {
	v := url.Values{}
	v.Set("state", state)

	// common.
	v.Set("code", code)
	v.Set("client_id", p.clientId)
	v.Set("client_secret", p.clientSecret)
	v.Set("redirect_uri", p.clientUrlRedirect)
	return v
}

func (p *Provider) tokenRequestOauth(ctx context.Context, code, state string) (*Token, error) {
	// yes so..
	v := p.buildFormTokenOauth(code, state)

	// ENSURE TLS verification.
	r, err := http.PostForm(p.urlToken, v)
	if err != nil {
		return nil, err
	}

	// replied with 200 ?
	if r.StatusCode != 200 {
		return nil, ErrNetwork
	}

	tokenBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	//fmt.Printf("Token Body:\n%s\n", tokenBody)

	tr, err := token.ParseResponse(tokenBody)
	if err != nil {
		return nil, err
	}

	t := Token{
		Access:  tr.AccessToken,
		Refresh: tr.RefreshToken,
		Id:      tr.IdToken,
	}

	return &t, nil
}

//func (p *Provider) tokenRequest(ctx context.Context, code string) (*token.Response, error) {
func (p *Provider) tokenRequest(ctx context.Context, code string) (*Token, error) {

	// yes so..
	v := p.buildFormToken(code)

	// ENSURE TLS verification.
	r, err := http.PostForm(p.urlToken, v)
	if err != nil {
		return nil, err
	}

	// replied with 200 ?
	if r.StatusCode != 200 {
		return nil, ErrNetwork
	}

	tokenBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	//fmt.Printf("Token Body:\n%s\n", tokenBody)

	tr, err := token.ParseResponse(tokenBody)
	if err != nil {
		return nil, err
	}

	t := Token{
		Access:  tr.AccessToken,
		Refresh: tr.RefreshToken,
		Id:      tr.IdToken,
	}

	return &t, nil
}

func (p *Provider) userInfoRequest(ctx context.Context, token Token) {
}
