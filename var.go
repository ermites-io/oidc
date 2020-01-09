// +build go1.12

package oidc

import "time"

var (
	DefaultStateTimeout = 5 * time.Minute
	// default openid scopes, this plus more.
	openidScopes = []string{
		"openid", "email", "profile",
	}
)
