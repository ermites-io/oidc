// +build go1.12

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

func grpcServer(svc *OidcService, hostport string) {

	nfd, err := net.Listen("tcp", hostport)
	if err != nil {
		panic(err)
	}

	fmt.Printf("start grpc service\n")
	grpcServer := grpc.NewServer()
	/*
		grpc.UnaryInterceptor(rpc.ForwardContextInterceptor),
		grpc.Creds(creds),
	*/

	RegisterOidcServer(grpcServer, svc)
	err = grpcServer.Serve(nfd)
	if err != nil {
		panic(err)
	}
}

func restServer(svc *OidcService, hostport string) {
	var dialopts []grpc.DialOption

	dialopts = append(dialopts, grpc.WithInsecure())
	dialopts = append(dialopts, grpc.WithDefaultCallOptions(grpc.FailFast(true)))

	nfd, err := grpc.Dial(grpcConnect, dialopts...)
	if err != nil {
		panic(err)
	}

	grpcClient := NewOidcClient(nfd)
	if err != nil {
		panic(err)
	}

	runtime.HTTPError = svc.OidcHandleHTTPError

	grpcmux := runtime.NewServeMux(
		/*
			//runtime.WithIncomingHeaderMatcher(hdrForwarder), // match headers we need to bring back to the gRPC stack
			runtime.WithOutgoingHeaderMatcher(headerRemover),
			runtime.WithMetadata(headerToMetadata),
		*/
		runtime.WithProtoErrorHandler(svc.OidcHandleHTTPError),    // handle our library specific error codes.
		runtime.WithForwardResponseOption(cookieOrRedirectMapper), // create the Location Header + state cookie for the auth
		runtime.WithMetadata(headerToMetadata),                    // get the cookie and fill it in metadatas.
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{OrigName: true, EmitDefaults: true}),
	)

	err = RegisterOidcHandlerClient(context.Background(), grpcmux, grpcClient)
	if err != nil {
		panic(err)
	}

	fwdopt := grpcmux.GetForwardResponseOptions()
	if err != nil {
		panic(err)
	}
	fmt.Printf("FORWARD OPTIONS: %d\n", len(fwdopt))

	fmt.Printf("hmm @ %p\n", cookieOrRedirectMapper)
	fmt.Printf("hmm @ %p\n", fwdopt[0])
	//httpmux := http.NewServeMux()
	/*
		httpmux.Handle("/redirect", grpcmux)
		httpmux.Handle("/session-redirect", grpcmux)
	*/

	// XXX one attempt/version
	//googleRedirect := http.RedirectHandler("http://www.google.com", http.StatusFound)
	/*
		gr := &googleRedirect{
			cf: cf,
		}
		httpmux.Handle("/login/google", gr)

		god := &googleAuth{
			cf: cf,
		}
		httpmux.Handle("/oauth", god)
	*/

	//httpmux.Handle("/login/github", grpcmux)
	//httpmux.Handle("/login/microsoft", grpcmux)
	//http.ListenAndServe(hostport, httpmux) // serve that on 8080
	fmt.Printf("ON FART\n")
	err = http.ListenAndServe(hostport, grpcmux) // serve that on 8080
	panic(err)
}
