// +build go1.12

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
)

var (
	errMissInformation = errors.New("information missing")
)

type OidcService struct {
	providers map[string]*OidcProvider
	//providerHash map[string]*OidcProvider

	loginFailUrl string
	loginOkUrl   string
}

/*
func sha256b64(str string) ([]byte, string) {
	tmpHash := sha3.Sum256([]byte(str))
	return tmpHash[:], base64.StdEncoding.EncodeToString(tmpHash[:])
}
*/

func NewOidcService(providers ...*OidcProvider) *OidcService {
	p := make(map[string]*OidcProvider) // might be unnecessary
	//ph := make(map[string]*OidcProvider)

	for i, v := range providers {
		// XXX to clean
		s256hex := sha256hex(v.name)
		//p[v.name] = v // might not be necessary and avoid collision we never know
		p[s256hex] = v
		fmt.Printf("[%d] register provider: %s / %s\n", i, v.name, s256hex)
	}

	// ok our oidc service is ready.
	o := OidcService{
		providers: p,
	}

	return &o
}

func (os *OidcService) SetFailUrl(url string) {
	os.loginFailUrl = url
}

func (os *OidcService) SetOkUrl(url string) {
	os.loginOkUrl = url
}

// the grpc callback rest gateway maps everything
func GetStateCookie(ctx context.Context) string {
	var nilstr string
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nilstr
	}

	stateCookie, ok := md[stateCookieName]
	if !ok || len(stateCookie) == 0 {
		return nilstr
	}

	return stateCookie[0]
}

/*
func (o *OidcService) Redirect(ctx context.Context, in *UrlData) (out *RedirectData, err error) {
	url := in.GetUrl()
	fmt.Printf("redirect: %s\n", url)
	//return nil, ErrRedirect
	return &RedirectData{Url: url}, ErrRedirect
}

func (o *OidcService) RedirectSession(ctx context.Context, in *UrlData) (out *RedirectSessionData, err error) {
	url := in.GetUrl()
	fmt.Printf("redirect-session: %s\n", in.GetUrl())
	return &RedirectSessionData{Id: uuid.New().String(), Url: url}, ErrRedirectSession
}
*/

// this function setup the environement and pass it to the
// forwardresponsehandler (the reply type contains our stuff) if we error here, unless we know exactly what/where to
// return and handle it in the error handler, if we error here the
// forwardresponsehandler NEVER runs and won't be able to set the appropriate
// cookies and all
func (o *OidcService) Login(ctx context.Context, in *IdpRequest) (out *SessionIdp, err error) {
	provider := in.GetProvider()

	// query a state and build the URL
	fmt.Printf("PROVIDER: %s\n", provider)

	s256hex := sha256hex(provider)

	p, ok := o.providers[s256hex]
	if !ok {
		fmt.Printf("unknown provider: %s\n", provider)
		err = ErrProviderAuthFailed
		return
	}

	nonce := uuid.New().String()

	//url, err := p.AuthURL()
	cookieValue, cookiePath, authUrl, err := p.RequestIdentityParams(nonce)
	if err != nil {
		fmt.Printf("authenticate '%s' error: %v\n", provider, err)
		err = ErrProviderAuthFailed
		return
	}

	// convert to a redirect baby!
	out = &SessionIdp{
		CookieState: cookieValue,
		CookiePath:  cookiePath,
		Url:         authUrl,
	}
	return
}

//
// that's where oidc is being redirected.
// and where we VERIFY the state or call to the authentication daemon that
// verify the state in this mockup we verify the state here.
// the cookie value is in the metadata, if not present we have an error for
// sure.
func (o *OidcService) Callback(ctx context.Context, in *IdpResponse) (out *SessionBackend, err error) {
	code := in.GetCode()                   // the code you use to request the token url
	state := in.GetState()                 // hmac hex version of the cookie state
	oidcerror := in.GetError()             // if the previous url was wrong you get an error here.
	oErrorDesc := in.GetErrorDescription() // if any..

	// check for metadata, basically is the cookie there..
	// but also check for other fucked up stuff..
	cookie := GetStateCookie(ctx)
	fmt.Printf("openid callback\ncookie: '%s'\ncode: '%s'\nstate: '%s'\nerror: '%s'\ndesc: '%s'\n\n",
		cookie,
		code,
		state,
		oidcerror,
		oErrorDesc)

	// XXX TODO check error & error description
	if len(cookie) == 0 || len(code) == 0 || len(state) == 0 || len(oidcerror) > 0 {
		return nil, ErrProviderAuthFailed
	}

	// Unpack Envelope
	// TODO: envelope.Unpack()
	// XXX is this a security risk?
	se, err := Unpack(cookie)
	if err != nil {
		return nil, ErrProviderAuthFailed
	}

	// now the state value is here...
	//sv := newOidcStateValue(c, state)
	// XXX sanitize inputs.
	provider := se.GetProvider()

	// TODO get provider
	/*
		provider, err := sv.Provider()
		if err != nil {
			return nil, ErrProviderAuthFailed
		}
	*/
	p, ok := o.providers[provider]
	if !ok {
		fmt.Printf("no provider '%s' found!\n", provider)
		return nil, ErrProviderAuthFailed
	}
	fmt.Printf("received provider: %s / %s\n", provider, p.name)

	// we received a reply including the cookie & the state from the
	// request, are they valid?
	/*
		if !p.IsValidState(sv) {
			fmt.Printf("state '%s' is not valid\n", state)
			return nil, ErrProviderAuthFailed
		}
	*/

	// TODO now check hmac(cookie) == state value
	// TODO now decrypt the cookie, to see which provider we're using..
	// this way we know where to send the code..
	if _, _, err = p.ValidateIdentityParams(ctx, code, cookie, state); err != nil {
		return nil, ErrProviderAuthFailed
	}

	// TODO check expiration, check aud == clientId, check nonce, check issuer match the provider issuer value

	// TODO send the code, provider client_secret, client_id, state, etc..
	// we receive a JWT as reply!

	// TODO check JWT signature vs provider JWKs CERTs retrieved...

	// TODO unpack JWT OID token

	// TODO check aud == client id

	// TODO check nonce vs nonce in decrypted state

	// TODO we're authenticated!!!!!!!

	// check for other fucked up things...
	fmt.Printf("oidc callback code: %s state: %s error: %s error desc: %s\n", code, state, oidcerror, oErrorDesc)

	//
	//err = ErrProviderAuthFailed
	return &SessionBackend{CookieSession: "valid_session_id", CookiePath: "/", Url: o.loginOkUrl}, nil
	return
}

//
// ok
//

/*
type OidcIdp struct {
	jwks string
	iss  string
}

type ProviderAuthorities struct {
	g map[string][]byte // google
	m map[string][]byte // microsoft
}
*/

/*
func GetKeys() {
	// this disable InsecureSkipVerify in tls.Config
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}

	// http client with transport
	client := &http.Client{Transport: tr}

	// post the token request
	resp, err := client.PostForm(g.cf.TokenUri, v)
	if err != nil {
		fmt.Printf("PostForm error: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	// max 256K why would it be bigger?
	n, err := io.CopyN(buf, resp.Body, 256*1024)
	fmt.Printf("response is %d bytes\n", n)

}
*/
