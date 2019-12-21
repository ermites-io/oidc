// +build go1.12

package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
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
	//jwk  jwkmap        // jwt verifier XXX types needs to change name
	auth *ProviderAuth // state provider
}

var (
	// default openid scopes, this plus more.
	openidScopes = []string{
		"openid", "email", "profile",
	}
)

func sha256hex(str string) string {
	tmpHash := sha3.Sum256([]byte(str))
	return base64.StdEncoding.EncodeToString(tmpHash[:])
}

func NewProvider(name, urlOidcConf string) (*Provider, error) {
	// parse the Oidc Configuration
	auth, token, issuer, jwks, err := parseOpenIdConfiguration(urlOidcConf)
	if err != nil {
		return nil, err
	}

	oidc := Provider{
		//urlRedirect: urlRedirect,
		name:     name,
		urlAuth:  auth,
		urlToken: token,
		urlJwks:  jwks,
		issuer:   issuer,
		scopes:   openidScopes,
		// the authorities check the jwt
		//jwt: jwtauth,
	}

	//fmt.Printf("PROVIDER: %v\n", oidc)
	return &oidc, nil
}

func (p *Provider) GetName() string {
	return p.name
}

func (p *Provider) buildFormToken(grantType, code string) url.Values {
	v := url.Values{}
	v.Set("grant_type", grantType)
	v.Set("code", code)
	v.Set("client_id", p.clientId)
	v.Set("client_secret", p.clientSecret)
	v.Set("redirect_uri", p.clientUrlRedirect)
	return v
}

func (p *Provider) tokenRequest(ctx context.Context, grantType, code string) (*tokenResponse, error) {
	// yes so..
	v := p.buildFormToken(grantType, code)

	// ENSURE TLS verification.
	r, err := http.PostForm(p.urlToken, v)
	if err != nil {
		return nil, err
	}

	tokenBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	fmt.Printf("Token Body:\n%s\n", tokenBody)

	t, err := parseTokenResponse(tokenBody)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (p *Provider) SetAuth(clientId, clientSecret, clientUrlRedirect string) error {
	var buf bytes.Buffer

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

	// get the jwks map
	// XXX might move into provider_auth
	jwtauth, err := jwkMapFromUrl(p.urlJwks)
	if err != nil {
		return err
	}

	// state auth is build from the client secret & client id.
	// derive 2 keys from clientSecret
	// pass is blake2 ( hkdf( sha3(clientSecret + clientId)) )
	// secret is blake2 ( hkdf( sha3(clientSecret + clientId + UrlRedirect)) )
	sha3ClientSecret := sha3.Sum512([]byte(clientSecret))
	sha3ClientId := sha3.Sum512([]byte(clientId))

	_, err = buf.Write(sha3ClientSecret[:])
	if err != nil {
		return err
	}

	_, err = buf.Write(sha3ClientId[:])
	if err != nil {
		return err
	}

	sha3KdfSalt := sha3.Sum512(buf.Bytes())

	// XXX ok this needs to move in the ProviderAuth part to avoid someone
	// using the auth without derivation.. users hey!
	// if for some reason there is a crypto biais or side channel, at least
	// the secret is derived and it does not leak the clientSecret directly

	// XXX key material handling is shit here :)
	hkdfReader := hkdf.New(sha3.New512, sha3ClientSecret[:], sha3KdfSalt[:], []byte(clientId))

	oidcpass := make([]byte, 64)
	oidcsecret := make([]byte, 64)

	// first 64 bytes of that reader -> pass (state encryption key)
	_, err = hkdfReader.Read(oidcpass)
	if err != nil {
		return err
	}

	// second 64 bytes of that reader -> secret (hmac state key)
	_, err = hkdfReader.Read(oidcsecret)
	if err != nil {
		return err
	}

	// auth contains the jwk stuff
	p.auth = NewProviderAuth(oidcpass, oidcsecret, jwtauth)

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

	//providerhex := Sha256hex(p.name)

	//cookieValue, cookiePath, Url, err := p.Authenticate(nonce)
	//cookie, state, err := p.auth.State(providerhex, nonce)
	cookie, state, err := p.auth.State(p.name, nonce)
	if err != nil {
		return
	}

	// this is harcoded for "now"
	//responseType := "code"
	responseType := "code"
	scope := strings.Join(p.scopes, " ")

	//fmt.Printf("SCOPE: %s\n", scope)

	cookieValue = cookie
	cookiePath = p.clientUrlRedirectPath // when we setAuth we set this value

	IdpRedirectUrl, err = p.buildUrlAuth(responseType, scope, nonce, state)
	return
}

func (p *Provider) ValidateIdToken(nonce string, idt *IdToken) error {
	// signed Idp nonce vs state embedded nonce
	if nonce != idt.claims.Nonce {
		return fmt.Errorf("invalid state nonce: %s vs idt.Nonce: %s", nonce, idt.claims.Nonce)
	}

	// Claims aud vs issuer
	if p.clientId != idt.claims.Aud {
		return fmt.Errorf("invalid aud: %s vs clientId: %s", idt.claims.Aud, p.clientId)
	}

	// claims iss vs issuer
	if p.issuer != idt.claims.Iss {
		return fmt.Errorf("invalid iss: %s vs issuer: %s", idt.claims.Iss, p.issuer)
	}

	// TODO: Expiration

	return nil
}

// XXX TODO: this is the real authentication
//func (o *Provider) ValidateIdentityParams(code string, sv *OidcStateValue) (accessToken, idToken string, err error) {
func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*IdToken, string, error) {
	var nilstr string

	grantType := "authorization_code"

	// YES, we unpack again for fuck sake!
	nonce, err := p.auth.ValidateState(cookie, state, 2*time.Minute)
	if err != nil {
		fmt.Printf("state '%s' is not valid: %v\n", state, err)
		return nil, nilstr, err
	}
	fmt.Printf("nonce found: %s\n", nonce)

	// yes so..
	// TODO: need to give back id token, access token, refresh token (if any)
	// needs to see how i will wire the usercontrolled handler.
	// return the accesstoken & refresh token too
	t, err := p.tokenRequest(ctx, grantType, code)
	if err != nil {
		return nil, nilstr, err
	}

	//fmt.Printf("ID TOKEN:\n%s\n", t.IdToken)

	idt, err := newIdToken(t.IdToken)
	if err != nil {
		//panic(err)
		return nil, nilstr, err
	}

	//fmt.Printf("NOW VERIFYING TOKEN SIGNATURE\n")
	// crypto verify the token.
	err = p.auth.VerifyIdToken(idt)
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
	//fmt.Printf("SIG: %v TOKEN: %v\n", err, idt)
	return idt, nilstr, nil
}
