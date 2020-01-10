// +build go1.12

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
)

type key struct {
	pub  interface{}
	hash crypto.Hash
}

type Keys map[string]*key

func (k Keys) Verify(kid string, input, sig []byte) error {
	jwk, ok := k[kid]
	if !ok {
		return fmt.Errorf("no jwk for kid: %s", kid)
	}

	return jwk.Verify(input, sig)
}

// RFC7518 section 3.4
func (jwk *key) Verify(input, sig []byte) error {
	key := jwk.pub
	hp := jwk.hash

	// for RSA we use THIS function..
	switch k := key.(type) {
	case *rsa.PublicKey:
		// hash input first..
		hasher := hp.New()
		hasher.Write(input)
		hashed := hasher.Sum(nil)

		// then verify
		// XXX security risk here, as error is NOT a constant
		// so any new external package could defeat our verification
		// by rsa.ErrVerification = nil
		return rsa.VerifyPKCS1v15(k, hp, hashed, sig)

	case *ecdsa.PublicKey:
		var r, s big.Int

		// as the rfc says.. the signature must be a 64 bytes sequece if
		// it is p-256/sha256
		if len(sig) != hp.Size()*2 {
			return ErrParse
		}

		hmark := hp.Size()
		rbuf := sig[:hmark]
		sbuf := sig[hmark:]

		//hashed := hp.New().Sum(input)
		hasher := hp.New()
		hasher.Write(input)
		hashed := hasher.Sum(nil)

		/*
			r := &big.Int{}
			s := &big.Int{}
		*/

		r.SetBytes(rbuf)
		s.SetBytes(sbuf)

		if ecdsa.Verify(k, hashed, &r, &s) {
			return nil
		}
	}
	return ErrUnsupported
}

func MapFromUrl(urls ...string) (Keys, error) {
	var jwks jwkSet
	jm := make(Keys)

	for _, url := range urls {
		//fmt.Printf("[%d] processing %s\n", iurl, url)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		respbuf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(respbuf, &jwks)
		if err != nil {
			return nil, err
		}

		for _, jwk := range jwks.Keys {
			//fmt.Printf("[%d] processing key...", ijwk)
			key, err := jwk.parse()
			if err != nil {
				//fmt.Printf("invalid (%v)\n", err)
				continue
			}
			//fmt.Printf("ok\n")
			jm[jwk.Kid] = key
		}

	}

	return jm, nil
}
