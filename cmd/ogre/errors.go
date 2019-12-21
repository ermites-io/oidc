package main

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	CodeRedirect        = 100 + iota
	CodeRedirectSession //
	CodeOidcFail
)

var (
	ErrRedirect        = status.Error(codes.Code(CodeRedirect), "redirect")
	ErrRedirectSession = status.Error(codes.Code(CodeRedirectSession), "redirect session")

	ErrProviderAuthFailed = status.Error(codes.Code(CodeOidcFail), "oidc failure")
)

func (os *OidcService) OidcHandleHTTPError(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	s, ok := status.FromError(err)
	if !ok {
		s = status.New(codes.Unknown, err.Error())
	}

	switch s.Code() {
	case CodeRedirect:
		w.WriteHeader(http.StatusFound)
	case CodeRedirectSession:
		w.WriteHeader(http.StatusFound)
	case CodeOidcFail:
		// location will be written here.
		//w.Header().Set("Location", "https://www.google.com/login-failed")
		w.Header().Set("Location", os.loginFailUrl)
		w.WriteHeader(http.StatusFound)
	default:
		runtime.DefaultHTTPError(ctx, mux, marshaler, w, r, err)
	}
}
