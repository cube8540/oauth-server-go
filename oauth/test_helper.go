package oauth

import (
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/client"
)

const (
	testSessionID = "test_sessions"

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
	Scopes:    testutils.ScopeList(testScopesArray...),
}

type TestToken struct {
	value     string
	expiresIn uint
	scope     string
}

func (t *TestToken) GetValue() string {
	return t.value
}

func (t *TestToken) IsActive() bool {
	return true
}

func (t *TestToken) GetClientID() string {
	return ""
}

func (t *TestToken) GetUsername() string {
	return ""
}

func (t *TestToken) GetScopes() string {
	return t.scope
}

func (t *TestToken) GetIssuedAt() uint {
	return 0
}

func (t *TestToken) GetExpiredAt() uint {
	return t.expiresIn
}
