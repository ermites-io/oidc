// +build go1.12

package auth

import (
	"crypto/hmac"
	"encoding/hex"
	"time"

	"github.com/ermites-io/oidc/internal/jwk"
	"github.com/ermites-io/oidc/internal/state"
	//"github.com/ermites-io/oidc/token"
	"golang.org/x/crypto/sha3"
)

//type ProviderAuth struct {
type Verifier struct {
	p   []byte   // password
	s   []byte   // secret
	jwk jwk.Keys // jwt verifier XXX types needs to change name
}

//func NewProviderAuth(password, secret []byte, jwkUrl string) (*ProviderAuth, error) {
func NewVerifier(password, secret []byte, jwkUrl string) (*Verifier, error) {
	pTmp := sha3.Sum512([]byte(password))
	sTmp := sha3.Sum512([]byte(secret))

	jwkauth, err := jwk.MapFromUrl(jwkUrl)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		p:   pTmp[:], // this is to encrypt the state
		s:   sTmp[:], // this is for the hmac part that goes in the URL
		jwk: jwkauth,
	}, nil
}

func hmac256(key, data []byte) ([]byte, error) {
	hm := hmac.New(sha3.New256, key)
	_, err := hm.Write(data)
	if err != nil {
		return nil, err
	}
	mac := hm.Sum(nil)
	return mac, nil
}

//func (pa *ProviderAuth) stateHmac(data []byte) (string, error) {
func (pa *Verifier) stateHmac(data []byte) (string, error) {
	var nilstr string

	mac, err := hmac256(pa.s, data)
	if err != nil {
		return nilstr, err
	}

	return hex.EncodeToString(mac), nil
}

//func (pa *ProviderAuth) stateHmacEqual(data []byte, stateHmac string) bool {
func (pa *Verifier) stateHmacEqual(data []byte, stateHmac string) bool {
	mac, err := hmac256(pa.s, data)
	if err != nil {
		return false
	}

	machex, err := hex.DecodeString(stateHmac)
	if err != nil {
		return false
	}

	return hmac.Equal(mac, machex)
}

//func (pa *ProviderAuth) State(provider, oidcNonce string) (string, string, error) {
func (pa *Verifier) State(provider, oidcNonce string) (string, string, error) {
	return pa.StateWithData(provider, oidcNonce, nil)
}

// duration would be 30 minutes -> NOW()
//func (oa *ProviderAuth) State(password, secret []byte, oidcNonce string) (*OidcStateValue, error) {
// let's limit that state otherwise...
// let's limit nonceSize also
//func (pa *ProviderAuth) StateWithData(provider, nonce string, userData []byte) (string, string, error) {
func (pa *Verifier) StateWithData(provider, nonce string, userData []byte) (string, string, error) {
	var nilstr string

	if len(userData) > state.MaxUserDataSize || len(nonce) > state.MaxUserDataSize {
		return nilstr, nilstr, ErrInvalid
	}

	d := state.NewData(nonce, userData)
	data, err := d.Pack()
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	e, err := state.NewEnvelope(provider)
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	err = e.Seal(pa.p, data)
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	// envelope.Pack()
	cookie, err := e.Pack()
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	// hmac
	state, err := pa.stateHmac([]byte(cookie))
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	// return
	return cookie, state, nil
}

//func (pa *ProviderAuth) ValidateState(cookie, state string, t time.Duration) (nonce string, err error) {
func (pa *Verifier) ValidateState(cookie, state string, t time.Duration) (nonce string, err error) {
	n, _, err := pa.ValidateStateWithData(cookie, state, t)
	return n, err
}

//func (pa *ProviderAuth) ValidateStateWithData(cookie, stateparam string, t time.Duration) (nonce string, userData []byte, err error) {
func (pa *Verifier) ValidateStateWithData(cookie, stateparam string, t time.Duration) (nonce string, userData []byte, err error) {
	var nilstr string

	if !pa.stateHmacEqual([]byte(cookie), stateparam) {
		return nilstr, nil, ErrInvalidState
	}

	e, err := state.ParseEnvelope(cookie)
	if err != nil {
		return nilstr, nil, err
	}

	data, err := e.Open(pa.p)
	if err != nil {
		return nilstr, nil, err
	}

	d, err := state.ParseData(data)
	if err != nil {
		return nilstr, nil, err
	}

	// is the state expired?
	stateCreationTime := time.Unix(d.Timestamp, 0)
	if time.Since(stateCreationTime) > t {
		return nilstr, nil, ErrInvalidState
	}

	return d.Nonce, d.Userdata, nil
}

//func (pa *Verifier) VerifyIdToken(idt *token.Id) error {
func (pa *Verifier) VerifyIdToken(kid string, input, sig []byte) error {
	return pa.jwk.Verify(kid, input, sig)
}
