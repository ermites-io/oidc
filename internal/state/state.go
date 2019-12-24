// +build go1.12

//go:generate protoc state.proto -I. --go_out=.

package state

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	MaxUserDataSize = 1024
)

//
// create the state
// setup the state as a cookie
// read the cookie to get the state value.
//
// returns
//
// that's one part of the auth necessary.
// remember the state goes in 2 ways...
// first part in a cookie we put the AEAD part of the state which includes user
// data, like the nonce being passed
// in the state URL parameter, we put the hmac of that state stored in the
// cookie of the browser trying to authenticate
// verification, will include retrieving that cookie and checking the hmac match
// with the cookie retrieved.

///
//
// ok let's try
// first state data.
//
//
func NewData(nonce string, userdata []byte) *Data {
	return &Data{
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Userdata:  userdata,
	}
}

// marshall
func (m *Data) Pack() ([]byte, error) {
	return proto.Marshal(m)
}

// unmarshal
//func UnpackData(blob []byte) (*Data, error) {
func ParseData(blob []byte) (*Data, error) {
	var sd Data
	err := proto.Unmarshal(blob, &sd)
	return &sd, err
}

/*
func UnpackStateData(blob []byte) (*StateData, error) {
	sd := StateData{}
	err = proto.Unmarshal(blob, &sd)
	if err != nil {
		return nil, err
	}
	return sd, nil
}
*/

//
//
//
// StateEnvelope
//
//
//
// an empty envelope
func NewEnvelope(provider string) (*Envelope, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return &Envelope{
		Provider: provider,
		Salt:     salt,
		Nonce:    nonce,
		//Payload:  payload,
	}, nil
}

func (m *Envelope) Seal(key, payload []byte) error {
	//var nilstr string
	var ad []byte

	salt := m.Salt
	nonce := m.Nonce

	// XXX hkdf should be enough.
	derivedKey := pbkdf2.Key(key, salt, 8192, 32, sha3.New256)
	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return err
	}

	// protect salt and nonce
	shasalt := sha3.Sum256(m.Salt)
	shanonce := sha3.Sum256(m.Nonce)
	shaprovider := sha3.Sum256([]byte(m.Provider))
	// XXX TOFIX and add in additional data
	//shaprovider, shaproviderstr := sha256b64(se.Provider)

	ad = append(ad, shasalt[:]...)
	ad = append(ad, shanonce[:]...)
	ad = append(ad, shaprovider[:]...)

	// now this is our raw state.
	m.Payload = aead.Seal(nil, nonce, payload, ad)
	return nil
}

func (m *Envelope) Open(key []byte) ([]byte, error) {
	var ad []byte

	salt := m.Salt
	nonce := m.Nonce

	// XXX hkdf should be enough.
	derivedKey := pbkdf2.Key(key, salt, 8192, 32, sha3.New256)
	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, err
	}

	// protect salt and nonce
	shasalt := sha3.Sum256(m.Salt)
	shanonce := sha3.Sum256(m.Nonce)
	shaprovider := sha3.Sum256([]byte(m.Provider))
	// XXX TOFIX and add in additional data
	//shaprovider, shaproviderstr := sha256b64(se.Provider)

	ad = append(ad, shasalt[:]...)
	ad = append(ad, shanonce[:]...)
	ad = append(ad, shaprovider[:]...)

	return aead.Open(nil, nonce, m.Payload, ad)
}

func (m *Envelope) Pack() (string, error) {
	//func (se *StateEnvelope) Pack() (string, error) {
	var nilstr string

	s, err := proto.Marshal(m)
	if err != nil {
		return nilstr, err
	}

	// that's  what goes into the cookie :)
	s64 := base64.RawURLEncoding.EncodeToString(s)
	return s64, nil
}

//func UnpackEnvelope(envelope string) (*Envelope, error) {
func ParseEnvelope(packed string) (*Envelope, error) {
	var e Envelope

	spb, err := base64.RawURLEncoding.DecodeString(packed)
	if err != nil {
		return nil, err
	}

	err = proto.Unmarshal(spb, &e)
	if err != nil {
		return nil, err
	}

	return &e, nil
}
