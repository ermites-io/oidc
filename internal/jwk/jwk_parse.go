package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type jwkSet struct {
	Keys   []jwkEntry
	Issuer string
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	// RSA fields
	RsaAlg string `json:"alg"`
	RsaE   string `json:"e"`
	RsaN   string `json:"n"`
	// EC Fields
	EccCrv string `json:"crv"`
	EccX   string `json:"x"`
	EccY   string `json:"y"`
}

func (jwe jwkEntry) validate() error {
	//fmt.Printf("entering validate for KID[%s]:\n%v\n", jwe.Kid, jwe)
	//fmt.Printf("kty: %s alg: %s\n", jwe.Kid, jwe.RsaAlg)
	if len(jwe.Kid) == 0 || len(jwe.Kty) == 0 {
		return ErrParse // no Key id)
	}

	switch jwe.Kty {
	case "RSA":
		//if len(jwe.RsaAlg) > 0 && // for some reason there is sometimes no alg...
		if len(jwe.RsaE) > 0 &&
			len(jwe.RsaN) > 0 {
			return nil
		}
	case "EC":
		if len(jwe.EccCrv) > 0 &&
			len(jwe.EccX) > 0 &&
			len(jwe.EccY) > 0 {
			return nil
		}
	}

	return ErrParse
}

func (jwe jwkEntry) parseRSA() (*key, error) {
	var e, n big.Int

	ebuf, err := base64.RawURLEncoding.DecodeString(jwe.RsaE)
	if err != nil {
		return nil, err
	}

	nbuf, err := base64.RawURLEncoding.DecodeString(jwe.RsaN)
	if err != nil {
		return nil, err
	}

	//e := &big.Int{}
	e.SetBytes(ebuf)
	n.SetBytes(nbuf)

	// our rebuilt key.
	r := rsa.PublicKey{
		E: int(e.Int64()),
		N: &n,
	}

	switch jwe.RsaAlg {
	case "RS256":
		return &key{pub: &r, hash: crypto.SHA256}, nil
	case "RS384":
		return &key{pub: &r, hash: crypto.SHA384}, nil
	case "RS512":
		return &key{pub: &r, hash: crypto.SHA512}, nil
	default:
		// If we don't know RsaAlg
		// we try to determine key len
		switch len(nbuf) {
		case 256:
			return &key{pub: &r, hash: crypto.SHA256}, nil
		case 384:
			return &key{pub: &r, hash: crypto.SHA384}, nil
		case 512:
			return &key{pub: &r, hash: crypto.SHA512}, nil
	}

	return nil, ErrParse
}

func (jwe jwkEntry) parseEC() (*key, error) {
	var x, y big.Int

	xbuf, err := base64.RawURLEncoding.DecodeString(jwe.EccX)
	if err != nil {
		return nil, err
	}

	ybuf, err := base64.RawURLEncoding.DecodeString(jwe.EccY)
	if err != nil {
		return nil, err
	}

	x.SetBytes(xbuf)
	y.SetBytes(ybuf)

	e := ecdsa.PublicKey{
		X: &x,
		Y: &y,
	}

	switch jwe.EccCrv {
	case "P-256":
		e.Curve = elliptic.P256()
		return &key{pub: &e, hash: crypto.SHA256}, nil
	case "P-384":
		e.Curve = elliptic.P384()
		return &key{pub: &e, hash: crypto.SHA384}, nil
	case "P-512":
		e.Curve = elliptic.P521()
		return &key{pub: &e, hash: crypto.SHA512}, nil
	}

	return nil, ErrParse
}

func (jwe jwkEntry) parse() (*key, error) {
	err := jwe.validate()
	if err != nil {
		return nil, err
	}

	switch jwe.Kty {
	case "RSA":
		return jwe.parseRSA()
	case "EC":
		return jwe.parseEC()
	}

	return nil, ErrParse
}
