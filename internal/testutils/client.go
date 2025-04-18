package testutils

import "oauth-server-go/oauth/client"

func ScopeList(c ...string) []client.Scope {
	var scopes []client.Scope
	for _, v := range c {
		scopes = append(scopes, client.Scope{Code: v})
	}
	return scopes
}
