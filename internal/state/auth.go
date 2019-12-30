// +build go1.12

package state

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	fmt "fmt"
	"time"

	//"github.com/ermites-io/oidc/token"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

//type ProviderAuth struct {
type Verifier struct {
	p []byte // password
	s []byte // secret
	//jwk jwk.Keys // jwt verifier XXX types needs to change name
}

//func NewProviderAuth(password, secret []byte, jwkUrl string) (*ProviderAuth, error) {
//func NewVerifier(password, secret []byte, jwkUrl string) (*Verifier, error) {
func NewVerifier(clientId, clientSecret string, jwkUrl string) (*Verifier, error) {
	var buf bytes.Buffer

	// state auth is build from the client secret & client id.
	// derive 2 keys from clientSecret
	// pass is blake2 ( hkdf( sha3(clientSecret + clientId)) )
	// secret is blake2 ( hkdf( sha3(clientSecret + clientId + UrlRedirect)) )
	sha3ClientSecret := sha3.Sum512([]byte(clientSecret))
	sha3ClientId := sha3.Sum512([]byte(clientId))

	_, err := buf.Write(sha3ClientSecret[:])
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(sha3ClientId[:])
	if err != nil {
		return nil, err
	}

	sha3KdfSalt := sha3.Sum512(buf.Bytes())

	// XXX ok this needs to move in the ProviderAuth part to avoid someone
	// using the auth without derivation.. users hey!
	// if for some reason there is a crypto biais or side channel, at least
	// the secret is derived and it does not leak the clientSecret directly

	// XXX key material handling is shit here :)
	hkdfReader := hkdf.New(sha3.New512, sha3ClientSecret[:], sha3KdfSalt[:], []byte(clientId))

	oidcpass := make([]byte, 1024)
	oidcsecret := make([]byte, 1024)

	// first 64 bytes of that reader -> pass (state encryption key)
	_, err = hkdfReader.Read(oidcpass)
	if err != nil {
		return nil, err
	}

	// second 64 bytes of that reader -> secret (hmac state key)
	_, err = hkdfReader.Read(oidcsecret)
	if err != nil {
		return nil, err
	}

	/*
		jwkauth, err := jwk.MapFromUrl(jwkUrl)
		if err != nil {
			return nil, err
		}
	*/

	pTmp := sha3.Sum512([]byte(oidcpass))
	sTmp := sha3.Sum512([]byte(oidcsecret))

	return &Verifier{
		p: pTmp[:], // this is to encrypt the state
		s: sTmp[:], // this is for the hmac part that goes in the URL
		//jwk: jwkauth,
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
func (pa *Verifier) New(provider, oidcNonce string) (string, string, error) {
	return pa.NewWithData(provider, oidcNonce, nil)
}

// duration would be 30 minutes -> NOW()
//func (oa *ProviderAuth) State(password, secret []byte, oidcNonce string) (*OidcStateValue, error) {
// let's limit that state otherwise...
// let's limit nonceSize also
//func (pa *ProviderAuth) StateWithData(provider, nonce string, userData []byte) (string, string, error) {
func (pa *Verifier) NewWithData(provider, nonce string, userData []byte) (string, string, error) {
	var nilstr string

	if len(userData) > MaxUserDataSize || len(nonce) > MaxUserDataSize {
		return nilstr, nilstr, ErrInvalid
	}

	d := NewData(nonce, userData)
	data, err := d.Pack()
	if err != nil {
		return nilstr, nilstr, ErrInvalid
	}

	e, err := NewEnvelope(provider)
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
func (pa *Verifier) Validate(cookie, state string, t time.Duration) (nonce string, err error) {
	n, _, err := pa.ValidateWithData(cookie, state, t)
	return n, err
}

//func (pa *ProviderAuth) ValidateStateWithData(cookie, stateparam string, t time.Duration) (nonce string, userData []byte, err error) {
func (pa *Verifier) ValidateWithData(cookie, stateparam string, t time.Duration) (nonce string, userData []byte, err error) {
	var nilstr string

	if !pa.stateHmacEqual([]byte(cookie), stateparam) {
		return nilstr, nil, ErrInvalidState
	}
	fmt.Printf("verification state equality: ok\n")

	e, err := ParseEnvelope(cookie)
	if err != nil {
		return nilstr, nil, err
	}
	fmt.Printf("verification envelope parsing: ok\n")

	data, err := e.Open(pa.p)
	if err != nil {
		return nilstr, nil, err
	}
	fmt.Printf("verification crypto open: ok\n")

	d, err := ParseData(data)
	if err != nil {
		return nilstr, nil, err
	}
	fmt.Printf("verification data parsing: ok\n")

	// is the state expired?
	stateCreationTime := time.Unix(d.Timestamp, 0)

	fmt.Printf("verification time expiration: %v vs %v\n", time.Now(), stateCreationTime)
	if time.Since(stateCreationTime) > t {
		return nilstr, nil, ErrInvalidState
	}

	return d.Nonce, d.Userdata, nil
}

//func (pa *Verifier) VerifyIdToken(idt *token.Id) error {
/*
func (pa *Verifier) VerifyIdToken(kid string, input, sig []byte) error {
	//return pa.jwk.Verify(kid, input, sig)
}
*/
