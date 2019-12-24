// +build go1.12

package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	//"github.com/ermites-io/oidc/token"
)

type key struct {
	pub  interface{}
	hash crypto.Hash
}

type Keys map[string]*key

//func (jm Keys) Verify(idt *token.Id) error {
func (jm Keys) Verify(kid string, input, sig []byte) error {
	/*
		var input []byte

		jwk, ok := jm[idt.Hdr.Kid]
		if !ok {
			return fmt.Errorf("no jwk for kid: %s", idt.Hdr.Kid)
		}

		input = append(input, idt.Hdr.Raw...)
		input = append(input, []byte(".")...)
		input = append(input, idt.Claims.Raw...)
	*/

	//fmt.Printf("VERIFYING INPUT: %s\n", input)
	jwk, ok := jm[kid]
	if !ok {
		return fmt.Errorf("no jwk for kid: %s", kid)
	}

	return jwk.Verify(input, sig)
}

/*
func NewJwkMap() (m jwkmap) {
	m = make(jwkmap)
	return
}
*/

// RSA JWK format
//
// { "kty": "RSA", "e": "AQAB", "alg": "RS256", "n": "2Kcpv4CxToeCKEIXznhqPg21MhCAP9DnX5s2_UdZ1bzOVhR8qiok_P8j7y8YF2M2Jc8r2btfCgJGFljbkttVc4XvnePePT-hGf9PekI1RUh7yk6PeG0kCJnmcWYgYXxXL8P0TDNHk3mWT4DlyN2CCclowGfRVLJbe1qC1NB2RXPycj0RfDNpIp5HWMZ8wPjI8wnrV5apoQK_sCz4P0CysAAskSBdhSR4Hz7L6mnheyV6NMxz3Brh1Dqlwh6J-ioh2RezguG807kxM1YqSUy2MvUFMi-DNi_G0LtSElEml4Y_otVk9EQycKqYqDhaa1RaqpFb21FtJ1w_8dVAOJ73-w", "use": "sig", "kid": "3db3ed6b9574ee3fcd9f149e59ff0eef4f932153" }
//

//
// EC JWK format
// {"kty":"EC", "crv":"P-256", "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
//
// help here:
// https://github.com/golang/crypto/blob/master/acme/jws.go#L89

// TODO: return the crypto.Hash
// XXX security risk, limit the size..
// kty == type
// alg == RSA + SHA bla
//func jwkParseRSAPub(jwk map[string]interface{}) (*rsa.PublicKey, crypto.Hash, error) {
//func jwkParseRSAPub(rawjwk map[string]interface{}) (*jwk, error) {
func parseJwkRSAPub(rawjwk map[string]interface{}) (*key, error) {
	e64 := rawjwk["e"].(string) // "AQAB"
	n64 := rawjwk["n"].(string) // "uNTSxjyvT0YtCoxUyEPahIq43tiK5lksGe5ZoE88AOJqXOLag5-wH1Ex5rsoQ628HhqtsEHmCQ2wT0-bl_Ol3EIAHLuCM0rmRiWevAEmDllpSldL2I3-lv_b-97BiRcW5KAAfF-0B_3zfNEGKF70l_iMDZ3j56IpDJwLDYma5C6Kh7r-fmoToKQTeasryoJWrDYlxqb_BC_egim_p5jLnc6cqY20ByVKdpnw7zok1-iLkl8nmEZMsznl-8KqVdZfk1NwPKKzMpTXvHvqC_9pgGFcwgvVpNZ6thk-L0UZs669hluHiq_eduSUHuwSgSpAtlloShPhJqj5tmRZ0P365Q"
	//kty := rawjwk["kty"].(string) // "RSA"
	//alg := jwk["alg"].(string) // "RS256"

	ebuf, err := base64.RawURLEncoding.DecodeString(e64)
	if err != nil {
		return nil, err
	}

	nbuf, err := base64.RawURLEncoding.DecodeString(n64)
	if err != nil {
		return nil, err
	}

	e := &big.Int{}
	n := &big.Int{}

	// hopla boum!
	e.SetBytes(ebuf)
	n.SetBytes(nbuf)

	r := rsa.PublicKey{
		E: int(e.Int64()),
		N: n,
	}

	// XXX microsoft does not send the alg in the jwk
	// google does though.. for now it's been used only for those 2
	switch {
	//case kty == "RSA" && alg == "RS256":
	case len(nbuf) == 256:
		return &key{pub: &r, hash: crypto.SHA256}, nil
	//case kty == "RSA" && alg == "RS384":
	case len(nbuf) == 384:
		return &key{pub: &r, hash: crypto.SHA384}, nil
	//case kty == "RSA" && alg == "RS512":
	case len(nbuf) == 512:
		return &key{pub: &r, hash: crypto.SHA384}, nil
	}

	//fmt.Printf("RSA Public Size: %d\n", r.Size())
	//return &r, nil
	return nil, ErrParse
}

// XXX security risk, limit the size..
// func jwkParseECPub(jwk map[string]interface{}) (*ecdsa.PublicKey, crypto.Hash, error) {
//func jwkParseECPub(rawjwk map[string]interface{}) (*jwk, error) {
func parseJwkECPub(rawjwk map[string]interface{}) (*key, error) {
	x64 := rawjwk["x"].(string)   // "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
	y64 := rawjwk["y"].(string)   // "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
	crv := rawjwk["crv"].(string) // "P-256"
	//kty := rawjwk["kty"].(string) // "EC"

	xbuf, err := base64.RawURLEncoding.DecodeString(x64)
	if err != nil {
		return nil, err
	}

	ybuf, err := base64.RawURLEncoding.DecodeString(y64)
	if err != nil {
		return nil, err
	}

	x := &big.Int{}
	y := &big.Int{}

	// hopla boum!
	x.SetBytes(xbuf)
	y.SetBytes(ybuf)

	e := ecdsa.PublicKey{
		X: x,
		Y: y,
	}

	switch {
	case crv == "P-256":
		e.Curve = elliptic.P256()
		return &key{pub: &e, hash: crypto.SHA256}, nil
	case crv == "P-384":
		e.Curve = elliptic.P384()
		return &key{pub: &e, hash: crypto.SHA384}, nil
	case crv == "P-521":
		e.Curve = elliptic.P521()
		return &key{pub: &e, hash: crypto.SHA512}, nil
	}

	return nil, ErrUnsupported
}

// RFC7518 section 3.4
//func (jwk *jwk) Verify(key interface{}, hp crypto.Hash, input, sig []byte) error {
func (jwk *key) Verify(input, sig []byte) error {
	key := jwk.pub
	hp := jwk.hash

	// for RSA we use THIS function..
	//func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
	// rsa.VerifyPKCS1v15(
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

		r := &big.Int{}
		s := &big.Int{}

		r.SetBytes(rbuf)
		s.SetBytes(sbuf)
		if ecdsa.Verify(k, hashed, r, s) {
			return nil
		}
	}
	return ErrUnsupported
}

// good start.. not perfect
//func jwkMap(jwksUris ...string) map[string]*jwk {
func MapFromUrl(jwksUris ...string) (Keys, error) {
	//jm := make(map[string]*jwk)
	//jm := NewJwkMap()
	jm := make(Keys)

	// we shall set InsecureSkipVerify
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	// http client with transport
	client := &http.Client{Transport: tr}
	for _, uri := range jwksUris {
		resp, err := client.Get(uri)
		if err != nil {
			fmt.Printf("Err on %s:%v\n", uri, err)
			//continue
			return nil, err
		}

		var respbuf bytes.Buffer
		_, err = io.Copy(&respbuf, resp.Body)
		if err != nil {
			fmt.Printf("Err read on %s:%v\n", uri, err)
			//continue
			return nil, err
		}
		defer resp.Body.Close()

		m := make(map[string]interface{})
		//m := jwkEnv{}
		err = json.Unmarshal(respbuf.Bytes(), &m)
		if err != nil {
			fmt.Printf("Unmarshal error on %s: %v\n", uri, err)
			//continue
			return nil, err
		}

		//	keysVector := m.keys
		keysVectorI, ok := m["keys"]
		if !ok {
			fmt.Printf("no keys to %s\n", uri)
			//continue
			return nil, err
		}

		keysVector := keysVectorI.([]interface{})

		//var k jwk
		//k := make(map[string]interface{})
		for _, key := range keysVector {

			//fmt.Printf("KEY I: %T\n", key)
			k := key.(map[string]interface{})
			//fmt.Printf("KEY: %v\n", key)

			kty := k["kty"].(string)
			kid := k["kid"].(string)

			/*
				var myk interface{}
				var hash crypto.Hash
			*/

			switch kty {
			case "RSA":
				fmt.Printf("RSA %s key found\n", kid)
				j, err := parseJwkRSAPub(k)
				if err != nil {
					fmt.Printf("error with kid: %s err: %v\n", kid, err)
					continue
				}
				jm[kid] = j
			case "EC":
				fmt.Printf("EC %s key found\n", kid)
				j, err := parseJwkECPub(k)
				if err != nil {
					fmt.Printf("error with kid: %s err: %v\n", kid, err)
					continue
				}
				jm[kid] = j
			default:
				fmt.Printf("unsupported key %s found\n", kid)
				continue
			}
		}
	}

	return jm, nil
}
