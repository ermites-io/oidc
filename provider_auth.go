// +build go1.12

package oidc

import (
	"crypto/hmac"
	"encoding/hex"
	"time"

	"github.com/ermites-io/oidc/internal/jwk"
	"github.com/ermites-io/oidc/internal/state"
	"github.com/ermites-io/oidc/token"
	"golang.org/x/crypto/sha3"
)

type ProviderAuth struct {
	p   []byte   // password
	s   []byte   // secret
	jwk jwk.Keys // jwt verifier XXX types needs to change name
}

func NewProviderAuth(password, secret []byte, jwkUrl string) (*ProviderAuth, error) {
	pTmp := sha3.Sum512([]byte(password))
	sTmp := sha3.Sum512([]byte(secret))

	jwkauth, err := jwk.MapFromUrl(jwkUrl)
	if err != nil {
		return nil, err
	}

	return &ProviderAuth{
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

func (pa *ProviderAuth) stateHmac(data []byte) (string, error) {
	var nilstr string

	mac, err := hmac256(pa.s, data)
	if err != nil {
		return nilstr, err
	}

	return hex.EncodeToString(mac), nil
}

func (pa *ProviderAuth) stateHmacEqual(data []byte, stateHmac string) bool {
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

func (pa *ProviderAuth) State(provider, oidcNonce string) (string, string, error) {
	return pa.StateWithData(provider, oidcNonce, nil)
}

// duration would be 30 minutes -> NOW()
//func (oa *ProviderAuth) State(password, secret []byte, oidcNonce string) (*OidcStateValue, error) {
// let's limit that state otherwise...
// let's limit nonceSize also
func (pa *ProviderAuth) StateWithData(provider, nonce string, userData []byte) (string, string, error) {
	var nilstr string

	if len(userData) > MaxUserDataSize || len(nonce) > MaxUserDataSize {
		return nilstr, nilstr, ErrInvalid
	}

	sd := state.NewData(nonce, userData)
	data, err := sd.pack()
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	e, err := state.NewEnvelope(provider)
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	err = e.seal(pa.p, data)
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	// envelope.Pack()
	cookie, err := state.pack(e)
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

func (pa *ProviderAuth) ValidateState(cookie, state string, t time.Duration) (nonce string, err error) {
	n, _, err := pa.ValidateStateWithData(cookie, state, t)
	return n, err
}

func (pa *ProviderAuth) ValidateStateWithData(cookie, state string, t time.Duration) (nonce string, userData []byte, err error) {
	var nilstr string

	if !pa.stateHmacEqual([]byte(cookie), state) {
		return nilstr, nil, ErrInvalidState
	}

	se, err := state.Unpack(cookie)
	if err != nil {
		return nilstr, nil, err
	}

	data, err := se.open(pa.p)
	if err != nil {
		return nilstr, nil, err
	}

	sd, err := state.unpackData(data)
	if err != nil {
		return nilstr, nil, err
	}

	// is the state expired?
	stateCreationTime := time.Unix(sd.Timestamp, 0)
	if time.Since(stateCreationTime) > t {
		return nilstr, nil, ErrInvalidState
	}

	return sd.Nonce, sd.Userdata, nil
}

func (pa *ProviderAuth) VerifyIdToken(idt *token.Id) error {
	return pa.jwk.Verify(idt)
}
