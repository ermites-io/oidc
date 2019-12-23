[![Documentation](https://godoc.org/github.com/ermites-io/oidc?status.svg)](http://godoc.org/github.com/ermites-io/oidc)      

oidc
====

An attempt at simple safe/secure OpenID Connect golang helpers package

Note: while it works already, it is a STABILIZATION-CLEANUPTHESHIT phase, which means
*WORK-IN-PROGRESS*, it will take several weeks to reach its first version and
then will be improved an updated to handle slightly more problematic, yet
commong use cases while trying to remain DEAD SIMPLE to use. 

Description
===========

This is an attempt to solve an issue we had, this is how we solved it, feedback is more than welcome.
Many new services/SaaS, try to provide the login with {Google, Microsoft, ...} functionnality, 
openid connect / oauth is a complexity squid with many security traps.

This package try to provide handlers/helpers to deal with a secure "login with" mechanism.

By only allowing the narrowed most common subset of params used and making sure they are safe/hard to attack, 
simple to use & robust.


How
===

Well, in rough terms, for services that needs to implement their RP and
provision on their side while insuring the Idp correctly authenticated the user,
we've put in place the following checks:

- state cookie for the callback only (identify the client/browser, secure, httponly, samestrict=lax)
- state cookie per provider initiated, a state cookie for one provider is not valid for another.
- state cookie timeout/expiration (per provider)
- state cookie envelope headers are protected by the AEAD.
- state cookie is generated on the initial 302 redirect.
- state cookie is an encrypted information valid for a single instanciated
  provider using securely derived keys (HKDF & PBKDF2).
- the `authorization_endpoint` url `state` parameter is `hmac-sha3-256(state cookie)`
  (linking them as a pair effectively)
- retrieving JWKs at the provider instantiation with TLS guarantees (once).
- JWT crypto verification for openId Connect usage ONLY, using the provider
  retrieved keys.
- RS256 / EC256 support ONLY (open id connect usage ONLY).
- JWT 'aud' / 'iss' / 'exp' / 'nonce' verification AFTER the crypto
  verification.
- uses ONE single callback url for all your providers.
- KISS, simple to use API.
- no gazillions dependencies.


Yes, But How
============
It goes in three steps:

## Register 

create your providers at your service start, in your service context, which
handle sort of map url -> provider
like: 

- https://.../login/google -> google
- https://.../login/microsoft -> microsoft
- etc..

```go
google, err := NewProvider("google", "google-openid-configuration")
// handle error

err = google.SetAuth("clientid.idp.com", "clientsecret2341321421", "https://login.myservice.io/callback")
// handle error
```

now register your providers in your context.. (that depends on your implementation obviously :))

```go
svc := NewOidcService(google, microsoft, ping)

```

Note: this is an example you can check oidc-ogre to have an implementation / toy example


## Login Handler

In your login with handler, whether it's a REST or gRPC etc.. (your
implementation).

```go
// generate a random nonce value, this is an example
nonce := uuid.New().String()                                                                                              

cookieValue, cookiePath, authUrl, err := p.RequestIdentityParams(nonce)                                                   
// handle error
```

that handler provides you with a cookie to set, a path for that cookie and the
url where to redirect for your 302.


## Open ID Connect Callback URL Handler

```go
...
code := in.GetCode()          // get the code parameter
state := in.GetState()        // get the state parameter (hmac hex version of the cookie state)
oidcerror := in.GetError()    // get the error parameter if any.
oErrorDesc := in.GetErrorDescription() // if any...
...
// get the cookie there.. 
cookie := GetStateCookie() // get the cookie
...
// unpack the envelope for the cookie payload
se, err := oidc.Unpack(cookie)
// handle error 

// get the provider to match in your context
provider := se.GetProvider()
// retrieve the provider context registered earlier and provide it the
params you received in your call back
idtoken, accesstoken, err = p.ValidateIdentityParams(ctx, code, cookie, state)
```

and there you are authenticated to your IdP the token request is handled by the
library along side verifying the reply for the openid connect attempt.
