[![Documentation](https://godoc.org/github.com/ermites-io/oidc?status.svg)](http://godoc.org/github.com/ermites-io/oidc)      

oidc
====

An attempt at simple safe/secure OpenID Connect golang helpers package

Note: while it works already, it is in a **opensource-stabilization-cleanup-alpha** phase, which means **WORK-IN-PROGRESS**. 
Some more time is necessary to reach its first public version and will continue to be improved/fixed as needed.
It will try to come common and slightly more problematic uses cases.

This is in **NO WAY** an RFC OpenID yada yada stack or anything, it's pragmatic
and it cover only a subset flows and features needed to implement secure login
through a 3rd party identity provider implementing openid connect (like google,
microsoft, ping federate, etc..).

hopefully it will help others to solve that problem for their app/infrastructure/etc..

Description
===========

This is an attempt to solve an issue we had, this is how we solved it, feedback is more than welcome.
Many new services/SaaS, try to provide the login with {Google, Microsoft, ...} functionnality, 
openid connect / oauth is a complexity squid with many security traps.

This package try to provide handlers/helpers to deal with a secure "login with" mechanism.

By only allowing the narrowed most common subset of params used and making sure they are safe/hard to attack, 
simple to use & robust.

Requirements
============

- go 1.12+
- protobuf for serialization, but may be we'll change that
- golang.org/x (crypto like sha3, xchacha20, etc..)


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

create your providers at your service start, in your service context, which handle sort of map url -> provider
like: 

- https://myservice/login/google -> "google"
- https://myservice/login/microsoft -> "microsoft"
- etc..

First parse the configuration (public) provided by your identity provider and initialize the provider 
(here the variable 'google').

```go
google, err := oidc.NewProvider("google", "google-openid-configuration")
// handle error
microsoft, err := oidc.NewProvider("microsoft", ms-openid-configuration")
// handle error
```

then add your provider auth information:

```
err = google.SetAuth("clientid.idp.com", "clientsecret2341321421", "https://login.myservice.io/callback")
// handle error
err = microsoft.SetAuth("microsoftclientid.com", "myothercliensecret", "https://login.myservice.io/callback")
// handle error
```

this part is your infrastructure/app specific, register your providers in your context.. (depends on your implementation obviously :))
example:

```go
svc := NewOidcService(google, microsoft, ...

```

Note: You can check oidc-ogre to have an implementation / toy example.


## Login Handler

You openid login handler will basically redirect to the identity provider
authorization URL.
In your login handler (whether it's REST or gRPC or..), generate a login request nonce, that will identify that login attempt. 

```go
// generate a random nonce value, this is an example
nonce := uuid.New().String()

cookieValue, cookiePath, authUrl, err := google.RequestIdentityParams(nonce)
// handle error
```

That handler provides you with a cookie to set, a path for the cookie (the callback url) and the prepopulated provider url 
where to redirect (302).


## Open ID Connect Callback URL Handler

After the user authenticated to the identity provider (google for example), it
will be redirected back to you, through your callback url with parameters to authenticate the
login request that originated from your login page, with the state, code and the
cookie that the browser wil reuse to access the callback url.

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
// params you received in your call back
idtoken, accesstoken, err = p.ValidateIdentityParams(ctx, code, cookie, state)
```

and there you are authenticated to your IdP the token request is handled by the
library along side verifying the reply for the openid connect attempt and the
cryptographic verification.

your app can now create a valid session for the user that just logged in and
create a context within your app.
