package oauth

import (
	"oauth-server-go/oauth/client"
)

const (
	testSessionID = "test_sessions"
	testUsername  = "username"

	testClientID      = 1
	testClientIDValue = "client_id"

	testLocalHost8080 = "http://localhost:8080"
	testLocalHost7070 = "http://localhost:7070"

	testAuthorizationCode  = "code"
	testAuthorizationState = "state"

	testTokenValue = "test_access_token"
	testExpiresIn  = 10
	testScope      = "scope_1 scope_2"
)

var testScopesArray = []string{"scope_1", "scope_2", "scope_3"}

var testClient = &client.Client{
	ID:        testClientID,
	ClientID:  testClientIDValue,
	Redirects: []string{testLocalHost8080, testLocalHost7070},
	Scopes:    client.ScopeList(testScopesArray...),
}
