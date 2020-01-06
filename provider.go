// +build go1.12

package oidc

import (
	"context"
	"encoding/base64"
	"fmt"
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

	// openid by default
	oauthOnly bool

	// auth parts
	state *state.Verifier // state provider
	jwk   jwk.Keys        // jwt verifier XXX types needs to change name
}

type Token struct {
	Access  string
	Refresh string
	Id      string
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

func NewProviderOauthOnly(name, urlAuth, urlToken string) (*Provider, error) {
	oidc := Provider{
		name:      name,
		urlAuth:   urlAuth,
		urlToken:  urlToken,
		scopes:    openidScopes,
		oauthOnly: true,
	}
	return &oidc, nil
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

func (p *Provider) validateIdToken(nonce string, idt *token.Id) error {
	// TODO: call idt.Validate(issuer, clientid, nonce)

	// signed Idp nonce vs state embedded nonce
	if idt.Claims.Nonce != nonce {
		return fmt.Errorf("invalid state idt.nonce: %s vs nonce: %s", idt.Claims.Nonce, nonce)
	}

	// Claims aud vs issuer
	if idt.Claims.Aud != p.clientId {
		return fmt.Errorf("invalid aud: %s vs clientId: %s", idt.Claims.Aud, p.clientId)
	}

	// claims iss vs issuer
	if idt.Claims.Iss != p.issuer {
		return fmt.Errorf("invalid iss: %s vs issuer: %s", idt.Claims.Iss, p.issuer)
	}

	// TODO: Expiration
	expirationTime := time.Unix(int64(idt.Claims.Exp), 0)
	nowTime := time.Now()
	if nowTime.After(expirationTime) {
		return fmt.Errorf("invalid exp: %v vs now: %v", expirationTime, time.Now())
	}

	return nil
}

// XXX TODO: this is the real authentication
//func (p *Provider) ValidateIdentityParams(code string, sv *OidcStateValue) (accessToken, idToken string, err error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Jwt, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Access, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.EndpointResponse, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (*token.Id, string, error) {
//func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (string, string, error) {
func (p *Provider) ValidateIdentityParams(ctx context.Context, code, cookie, state string) (t *Token, err error) {
	//var nilstr string

	// YES, we unpack again for fuck sake!
	nonce, err := p.state.Validate(cookie, state, DefaultStateTimeout)
	if err != nil {
		fmt.Printf("state '%s' is not valid: %v\n", state, err)
		return nil, err
	}

	// authentification is finished since we don't have token ids etc..
	if p.oauthOnly {
		tr, err := p.tokenRequestOauth(ctx, code, state)
		if err != nil {
			fmt.Printf("TOKEN REQUEST OAUTH ERR: %v\n", err)
			return nil, err
		}

		fmt.Printf("Tokens: %v\n", tr)

		return tr, nil
	}

	// yes so..
	// TODO: need to give back id token, access token, refresh token (if any)
	// needs to see how i will wire the usercontrolled handler.
	// return the accesstoken & refresh token too
	tr, err := p.tokenRequest(ctx, code)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("%s\n", t)
	fmt.Printf("Tokens: %v\n", tr)

	idt, err := token.Parse(tr.Id)
	if err != nil {
		//panic(err)
		return nil, err
	}

	// create functions..
	kid, blob, sig := idt.GetVerifyInfo()
	err = p.jwk.Verify(kid, blob, sig)
	if err != nil {
		//panic(err)
		return nil, err
	}

	// TODO here we verify the issuer, the aud, the nonce, etc.. etc.. etc..
	err = p.validateIdToken(nonce, idt)
	if err != nil {
		//panic(err)
		return nil, err
	}

	// show the token.
	//return t.IdToken, t.AccessToken, nil
	return tr, nil
}

func (p *Provider) GetName() string {
	return p.name
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
