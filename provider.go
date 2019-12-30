// +build go1.12

package oidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	// just to get the cookie..
	"github.com/ermites-io/oidc/internal/jwk"
	"github.com/ermites-io/oidc/internal/state"
	"github.com/ermites-io/oidc/internal/token"
)

var (
	DefaultStateTimeout = 5 * time.Minute
	// default openid scopes, this plus more.
	openidScopes = []string{
		"openid", "email", "profile",
	}
)

type Provider struct {
	name                  string
	clientId              string   // provider specific
	clientSecret          string   // provider specific
	clientUrlRedirect     string   // redirect Url setup at your idp.
	clientUrlRedirectPath string   // for the cookie
	urlAuth               string   // where to redirect when you click "login with <provider>" to start the openid sequence
	urlToken              string   // where to request the token in the sequence.
	urlJwks               string   // where are the authorities for the JWTs
	issuer                string   // who issued the certificates.
	scopes                []string // we might need more..scopes

	// auth parts
	state *state.Verifier // state provider
	jwk   jwk.Keys        // jwt verifier XXX types needs to change name
}

func sha256hex(str string) string {
	tmpHash := sha3.Sum256([]byte(str))
	return base64.StdEncoding.EncodeToString(tmpHash[:])
}

func NewProvider(name, urlOidcConf string) (*Provider, error) {
	// parse the Oidc Configuration
	authz, token, issuer, jwks, err := parseOpenIDConfiguration(urlOidcConf)
	if err != nil {
		return nil, err
	}

	oidc := Provider{
		//urlRedirect: urlRedirect,
		name:     name,
		urlAuth:  authz,
		urlToken: token,
		urlJwks:  jwks,
		issuer:   issuer,
		scopes:   openidScopes,
	}

	//fmt.Printf("PROVIDER: %v\n", oidc)
	return &oidc, nil
}

func (p *Provider) GetName() string {
	return p.name
}

func (p *Provider) buildFormToken(code string) url.Values {
	// grantType for authorization_code flows
	// code MUST be part of the grand types
	grantType := "authorization_code"

	v := url.Values{}
	v.Set("grant_type", grantType)
	v.Set("code", code)
	v.Set("client_id", p.clientId)
	v.Set("client_secret", p.clientSecret)
	v.Set("redirect_uri", p.clientUrlRedirect)
	return v
}

func (p *Provider) tokenRequest(ctx context.Context, code string) (*token.Response, error) {

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

	t, err := token.ParseResponse(tokenBody)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (p *Provider) SetAuth(clientId, clientSecret, clientUrlRedirect string) error {
	//var buf bytes.Buffer

	// ok setup the basics
	p.clientId = clientId
	p.clientSecret = clientSecret // TODO to xor in memory
	p.clientUrlRedirect = clientUrlRedirect

	// want to avoid parsing all the time
	u, err := url.ParseRequestURI(p.clientUrlRedirect)
	if err != nil {
		return err
	}
	p.clientUrlRedirectPath = u.RequestURI()

	// auth contains the jwk stuff
	//p.auth = NewProviderAuth(oidcpass, oidcsecret, jwtauth)
	//p.auth, err = auth.NewVerifier(oidcpass, oidcsecret, p.urlJwks)
	p.state, err = state.NewVerifier(clientId, clientSecret, p.urlJwks)
	if err != nil {
		return err
	}

	p.jwk, err = jwk.MapFromUrl(p.urlJwks)
	if err != nil {
		return err
	}

	return nil
}

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

// XXX TODO: probably need to be renamed properly
func (p *Provider) RequestIdentityParams(nonce string) (cookieValue, cookiePath, IdpRedirectUrl string, err error) {
	cookie, state, err := p.state.New(p.name, nonce)
	if err != nil {
		return
	}

	// this is harcoded for "now"
	responseType := "code"
	scope := strings.Join(p.scopes, " ")

	//fmt.Printf("SCOPE: %s\n", scope)

	cookieValue = cookie
	cookiePath = p.clientUrlRedirectPath // when we setAuth we set this value

	IdpRedirectUrl, err = p.buildUrlAuth(responseType, scope, nonce, state)
	return
}

func (p *Provider) ValidateIdToken(nonce string, idt *token.Id) error {
	// TODO: call idt.Validate(issuer, clientid, nonce)

	// signed Idp nonce vs state embedded nonce
	if nonce != idt.Claims.Nonce {
		return fmt.Errorf("invalid state nonce: %s vs idt.Nonce: %s", nonce, idt.Claims.Nonce)
	}

	// Claims aud vs issuer
	if p.clientId != idt.Claims.Aud {
		return fmt.Errorf("invalid aud: %s vs clientId: %s", idt.Claims.Aud, p.clientId)
	}

	// claims iss vs issuer
	if p.issuer != idt.Claims.Iss {
		return fmt.Errorf("invalid iss: %s vs issuer: %s", idt.Claims.Iss, p.issuer)
	}

	// TODO: Expiration

	return nil
}

// XXX TODO: this is the real authentication
//func (p *Provider) ValidateIdentityParams(code string, sv *OidcStateValue) (accessToken, idToken string, err error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Jwt, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Access, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.EndpointResponse, string, error) {
func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Id, string, error) {
	var nilstr string

	// YES, we unpack again for fuck sake!
	nonce, err := p.state.Validate(cookie, state, DefaultStateTimeout)
	if err != nil {
		fmt.Printf("state '%s' is not valid: %v\n", state, err)
		return nil, nilstr, err
	}
	//fmt.Printf("nonce found: %s\n", nonce)

	// yes so..
	// TODO: need to give back id token, access token, refresh token (if any)
	// needs to see how i will wire the usercontrolled handler.
	// return the accesstoken & refresh token too
	t, err := p.tokenRequest(ctx, code)
	if err != nil {
		return nil, nilstr, err
	}

	fmt.Printf("%s\n", t)
	fmt.Printf("ID TOKEN:\n%s\n", t.IdToken)

	idt, err := token.Parse(t.IdToken)
	if err != nil {
		//panic(err)
		return nil, nilstr, err
	}

	// create functions..
	kid, blob, sig := idt.GetVerifyInfo()
	err = p.jwk.Verify(kid, blob, sig)
	if err != nil {
		//panic(err)
		return nil, nilstr, err
	}

	// TODO here we verify the issuer, the aud, the nonce, etc.. etc.. etc..
	err = p.ValidateIdToken(nonce, idt)
	if err != nil {
		//panic(err)
		return nil, nilstr, err
	}

	// show the token.
	return idt, nilstr, nil
}

// return provider from the cookie.
func GetProvider(cookie string) (string, error) {
	var nilstr string

	e, err := state.ParseEnvelope(cookie)
	if err != nil {
		return nilstr, err
	}

	return e.GetProvider(), nil
}
