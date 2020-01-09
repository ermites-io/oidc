[![Documentation](https://godoc.org/github.com/ermites-io/oidc?status.svg)](http://godoc.org/github.com/ermites-io/oidc)      

oidc
====

A simple hardened golang OpenID Connect client helpers package following/using part of the OpenID Connect Core framework.


Description
===========

This is an attempt to create a simple, hardened, robust, re-usable package for delegated login process using OpenID Connect Core.
Feedback is more than welcome.

Many new services/SaaS have to provide the "login with" {Google, Microsoft, ...} functionnality, openid connect / oauth is a 
complexity squid with many security traps and potential shortcomings

It **ONLY** support and harden:
- Authorization Code Flow

We do **NOT** support (as it is not the purpose of this package):
- Implicit Flow
- Hybrid Flow

We had to provide the functionnality as part of a project, we wanted something we understood properly, hardened by default & KISS.
We were not at ease with x/oauth2 (although it is similar in the API) and building an overlay on top of it seemed to introduce
too much complexity.

Later the package will lean towards interroperability with x/oauth2 calls, by using/exporting to the x/oauth2 package type Token.

Hopefully this might help others trying implement secure delegated login in their app/infrastructure/etc..

**WORK IN PROGRESS** but close to 0.1.0.


Requirements
============

- go 1.12+
- protobuf for serialization, but may be we'll change that
- golang.org/x (crypto like sha3, xchacha20, etc..)


How is it hardened
==================

Well, in rough terms, services needs to implement their RP/Client and provision on their side while insuring the Idp 
correctly authenticated the user, the library generates parameters for the developer to use in its REST or gRPC
API in order to harden the delegated login process.

There are 2 main helpers defined: RequestIdentityParams, ValidateIdentityParams.

On login, oidc.(Provider).RequestIdentityParams generates 3 parameters:
- cookie value 
- cookie path value 
- provider specific authorization_endpoint redirect location generated url

On Callback, oidc.(Provider).ValidateIdentityParams verify 3 received parameters:
- cookie value
- state
- code.

The library handles the request to the Identity provider through HTTPS ONLY using your local SSL CAs.

oidc uses the following to harden the protocol a tiny bit:

- hardened cookie value & path are generated to be securely set by the service developer on the login redirect.
- generated cookie values are wrapped encrypted blobs using provider specific keys & lifetime secured with xchacha20-poly1305 AEAD.
- the state included in the generated authorization_endpoint url is associated with the generated cookie using HMAC-SHA3-512 
  (effectively associating the browser making the authentication request).
- encryption & HMAC keys are derived (HKDF/PBKDF2) using provider specific data (client id, client secret, etc..) at provider instantiation.
- The state oidc cookie embed & secure the following data:
  * provider name.
  * openid connect nonce value.
  * size limited user controlled data.
  * expiration time.
- OpenID provider JWK keys are retrieved (TLS only) and cached in memory at provider instantiation.
- JWT crypto verification happens ONLY if the state/cookie verification pass.
- nonce verification happens ONLY if the JWT verification pass.
- JWT issuer, audience and expiration verification happens ONLY after all above pass.
- RS256 / RS384 / RS512 / ES256 / ES384 / ES512 support ONLY (PS256/384/512 support coming)
- uses ONE single callback url for all your providers.
- KISS, simple to use API (3 calls).
- no gazillions dependencies, protobuf + standard golang libraries ONLY.


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
err = google.SetAuth("gclientid1", "googleclientsecret2", "https://login.myservice.io/cb")
// handle error
err = microsoft.SetAuth("msclientid", "mscliensecret", "https://login.myservice.io/cb")
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

TODO
====

- HTTPs connections cert pinning.
- PKCE support (if necessary as we already use the nonce in the state)


Threat Modeling
===============

- TODO
- mitm
- cb bruteforce
- token reuse
