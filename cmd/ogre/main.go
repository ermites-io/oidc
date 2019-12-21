// +build go1.12

package main

//go:generate protoc oidc.proto -I. -I$HOME/tools/pb3/include -I/home/rival/dev/go/pkg/mod/github.com/grpc-ecosystem/grpc-gateway@v1.9.5/third_party/googleapis --go_out=plugins=grpc:.
//go:generate protoc oidc.proto -I. -I$HOME/tools/pb3/include -I/home/rival/dev/go/pkg/mod/github.com/grpc-ecosystem/grpc-gateway@v1.9.5/third_party/googleapis --grpc-gateway_out=logtostderr=true:.

import (
	"fmt"

	"github.com/ermites-io/oidc"
)

const (
	grpcConnect = "127.0.0.1:8888"
	restConnect = "127.0.0.1:8000"
	oauthConfig = "oauth_conf.json"
)

//
//
// we will listen on 2 ports
// 8888: GRPC service
//
// 80: REST gateway

//
// ok OIDC services NEEDS to make this discovery.
//

/*
type jwkEnv struct {
	keys []string `json:"keys"`
}
*/

func main() {
	fmt.Printf("oauth dev service\n")

	google, err := oidc.NewProvider("google", "./google-openid-configuration")
	if err != nil {
		panic(err)
	}
	// setup the new provider..
	err = google.SetAuth("118314873199clientid.idp.com", "clientsecret2341321421", "https://login.ermite.io/oauth")
	if err != nil {
		panic(err)
	}
	fmt.Printf("GOOGLE Provider: %v\n", google)

	/*
		microsoft, err := NewProvider("microsoft", "./microsoft-openid-configuration")

		// setup the new provider..
		microsoft.SetClient("118314873199.microsoftblablacontent.com", "dkjsaldasjlkjwc39939re1", "https://login.ermite.io/oauth")
		fmt.Printf("MICROSOFT Provider: %v\n", google)
	*/

	// add providers
	svc := NewOidcService(google)
	svc.SetFailUrl("https://login.ermite.io/login-failed")
	svc.SetOkUrl("https://login.ermite.io/login-ok")

	//
	// start grpc
	go grpcServer(svc, grpcConnect)

	// then rest
	//restServer(restService, &oaf)
	restServer(svc, restConnect)

	// STATE CREATION / VERIFICATION TPW
	//func State(password, secret []byte, oidcNonce string) (*OidcState, error) {
	//oidcNonce := uuid.New().String()

	//
	/*
		parseOidcConf("./google-openid-configuration")
		parseOidcConf("./microsoft-openid-configuration")
	*/

	// password and secret can be secret as they only need to be consistent
	// across a set of oidc logging systems
	// so it needs to be a parameter.
	//
	//
	// i would need something like registerOidc("endpoint", "openid configuration")
	// :
	// oidc.NewProvider("google", "google-openid-conf")
	// oidc.NewProvider("microsoft", "microsoft-openid-conf")
	// oidc.NewProvider("github", "ping-openid-conf")
}
