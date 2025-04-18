package token

import (
	"github.com/stretchr/testify/assert"
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"testing"
	"time"
)

const (
	testTokenValue        = "TEST_TOKEN_ID"
	testRefreshTokenValue = "TEST_REFRESH_VALUE"
	testTokenID           = 1
	testRefreshTokenID    = 1

	testClientID    = 1
	testRedirectURI = "http://localhost:8080"

	testAuthCodeValue = "AUTH_CODE"
	testCodeChallenge = "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2"

	testUsername = "USERNAME"
	testPassword = "PASSWORD"
)

var testScopeArray = []string{"scope_1", "scope_2", "scope_3"}

func fixedTokenIDGenerator(id string) IDGenerator {
	return func() string {
		return id
	}
}

type mockStore struct {
	findAccessTokenByValue  func(v string) (*Token, error)
	findRefreshTokenByValue func(v string) (*RefreshToken, error)
	refresh                 func(oldRefreshToken *RefreshToken, newToken *Token, fn func(t *Token) *RefreshToken) error

	savedToken   *Token
	savedRefresh *RefreshToken

	deletedToken   *Token
	deletedRefresh *RefreshToken
}

func (m *mockStore) Save(t *Token, fn func(t *Token) *RefreshToken) error {
	m.savedToken = t
	if refresh := fn(t); refresh != nil {
		m.savedRefresh = refresh
	}
	return nil
}

func (m *mockStore) FindAccessTokenByValue(v string) (*Token, error) {
	return m.findAccessTokenByValue(v)
}

func (m *mockStore) FindRefreshTokenByValue(v string) (*RefreshToken, error) {
	return m.findRefreshTokenByValue(v)
}

func (m *mockStore) Refresh(oldRefreshToken *RefreshToken, newToken *Token, fn func(t *Token) *RefreshToken) error {
	m.deletedRefresh = oldRefreshToken
	m.deletedToken = oldRefreshToken.Token
	m.savedToken = newToken
	if refresh := fn(newToken); refresh != nil {
		m.savedRefresh = refresh
	}
	return nil
}

func authorizationCodeConsumer(then string, rtn *code.AuthorizationCode) AuthCodeConsume {
	return func(ce string) (*code.AuthorizationCode, error) {
		if ce == then {
			return rtn, nil
		}
		return nil, code.ErrNotFound
	}
}

type tokenGrantExpected struct {
	returnedToken        *Token
	returnedRefreshToken *RefreshToken

	savedToken        *Token
	savedRefreshToken *RefreshToken

	deletedToken        *Token
	deletedRefreshToken *RefreshToken

	err error
}

type tokenGrantTestCase struct {
	name        string
	store       *mockStore
	idGenerator IDGenerator
	client      *client.Client
	request     *pkg.TokenRequest
	expect      tokenGrantExpected
}

///////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Authorization Code Flow ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

type authCodeFlowTestCase struct {
	tokenGrantTestCase
	consumer AuthCodeConsume
}

func TestAuthorizationCodeFlow_Generate(t *testing.T) {
	tests := []authCodeFlowTestCase{
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "요청에 인가 코드가 없을 경우 ErrInvalidRequest 발생",
				store: &mockStore{},
				request: &pkg.TokenRequest{
					Code: "",
				},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "인가코드를 찾을 수 없을 경우 ErrTokenCannotGrant 발생",
				store: &mockStore{},
				client: &client.Client{
					ID: testClientID,
				},
				request: &pkg.TokenRequest{
					Code: testAuthCodeValue,
				},
				expect: tokenGrantExpected{
					err: ErrTokenCannotGrant,
				},
			},
			consumer: func(_ string) (*code.AuthorizationCode, error) {
				return nil, code.ErrNotFound
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "인가 코드의 클라이언트와 요청 클라이언트가 다른 경우 ErrUnauthorized 발생",
				store: &mockStore{},
				client: &client.Client{
					ID: testClientID,
				},
				request: &pkg.TokenRequest{
					Code: testAuthCodeValue,
				},
				expect: tokenGrantExpected{
					err: ErrUnauthorized,
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID: 2,
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "인가 코드가 만료 되었을 경우 ErrTokenCannotGrant 발생",
				store: &mockStore{},
				client: &client.Client{
					ID: testClientID,
				},
				request: &pkg.TokenRequest{
					Code: testAuthCodeValue,
				},
				expect: tokenGrantExpected{
					err: ErrTokenCannotGrant,
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID:  testClientID,
				ExpiredAt: time.Now().Add(-1 * time.Second), // 1초 전에 만료
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "인가 코드 code_challenge 검증 실패시 ErrInvalidRequest 발생",
				store: &mockStore{},
				client: &client.Client{
					ID: testClientID,
				},
				request: &pkg.TokenRequest{
					Code:         testAuthCodeValue,
					CodeVerifier: "wrong verifier",
				},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID:            testClientID,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallenge:       testCodeChallenge,
				CodeChallengeMethod: pkg.ChallengePlan, // PLAN 방식을 사용
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "리다이렉트 URL이 일치 하지 않는 경우 ErrInvalidRequest 발생",
				store: &mockStore{},
				client: &client.Client{
					ID:        testClientID,
					Redirects: []string{testRedirectURI},
				},
				request: &pkg.TokenRequest{
					Code:         testAuthCodeValue,
					CodeVerifier: testCodeChallenge,
					Redirect:     "http://wrong-redirect-url.com",
				},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID:            testClientID,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallenge:       testCodeChallenge,
				CodeChallengeMethod: pkg.ChallengePlan,
				Redirect:            testRedirectURI,
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:        "클라이언트가 공개 클라이언트인 경우 리플레시 토큰을 생성 하지 않음",
				store:       &mockStore{},
				idGenerator: fixedTokenIDGenerator(testTokenValue),
				client: &client.Client{
					ID:        testClientID,
					Type:      pkg.ClientTypePublic,
					Redirects: []string{testRedirectURI},
				},
				request: &pkg.TokenRequest{
					Code:         testAuthCodeValue,
					CodeVerifier: testCodeChallenge,
					Redirect:     testRedirectURI,
				},
				expect: tokenGrantExpected{
					savedToken: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList(testScopeArray...),
					},
					savedRefreshToken: nil,
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID:            testClientID,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallenge:       testCodeChallenge,
				CodeChallengeMethod: pkg.ChallengePlan,
				Redirect:            testRedirectURI,
				Username:            testUsername,
				Scopes:              testutils.ScopeList(testScopeArray...),
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:        "클라이언트가 공개 클라이언트가 아닌 경우 리플레시 토큰을 생성 함",
				store:       &mockStore{},
				idGenerator: fixedTokenIDGenerator(testTokenValue),
				client: &client.Client{
					ID:        testClientID,
					Type:      pkg.ClientTypeConfidential,
					Redirects: []string{testRedirectURI},
				},
				request: &pkg.TokenRequest{
					Code:         testAuthCodeValue,
					CodeVerifier: testCodeChallenge,
					Redirect:     testRedirectURI,
				},
				expect: tokenGrantExpected{
					savedToken: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList(testScopeArray...),
					},
					savedRefreshToken: &RefreshToken{
						Value: testTokenValue,
						Token: &Token{
							Value:    testTokenValue,
							ClientID: testClientID,
							Username: testUsername,
							Scopes:   testutils.ScopeList(testScopeArray...),
						},
					},
				},
			},
			consumer: authorizationCodeConsumer(testAuthCodeValue, &code.AuthorizationCode{
				ClientID:            testClientID,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallenge:       testCodeChallenge,
				CodeChallengeMethod: pkg.ChallengePlan,
				Redirect:            testRedirectURI,
				Username:            testUsername,
				Scopes:              testutils.ScopeList(testScopeArray...),
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewAuthorizationCodeFlow(tc.store, tc.consumer)
			srv.IDGenerator = tc.idGenerator

			_, _, err := srv.Generate(tc.client, tc.request)
			tokenGrantAssert(t, tc.tokenGrantTestCase, err)
		})
	}
}

///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// Implicit Flow ////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

type implicitFlowTestCase struct {
	tokenGrantTestCase
	authorizationRequest *pkg.AuthorizationRequest
}

func TestImplicitFlow_Generate(t *testing.T) {
	tests := []implicitFlowTestCase{
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "State 파라미터를 입력하지 않았을 경우 ErrInvalidRequest 발생",
				store: &mockStore{},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
			authorizationRequest: &pkg.AuthorizationRequest{
				State: "",
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:        "엑세스 토큰 생성",
				store:       &mockStore{},
				idGenerator: fixedTokenIDGenerator(testTokenValue),
				client: &client.Client{
					ID:     testClientID,
					Scopes: testutils.ScopeList("scope_1", "scope_2", "scope_3"),
				},
				expect: tokenGrantExpected{
					savedToken: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList("scope_1", "scope_2"), // 요청한 스코프를 할당 받아야 한다.
					},
					savedRefreshToken: nil,
				},
			},
			authorizationRequest: &pkg.AuthorizationRequest{
				State:    "ABCD",
				Username: testUsername,
				Scopes:   "scope_1 scope_2",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewImplicitFlow(tc.store)
			srv.IDGenerator = tc.idGenerator

			_, err := srv.Generate(tc.client, tc.authorizationRequest)
			tokenGrantAssert(t, tc.tokenGrantTestCase, err)
		})
	}
}

func fixedAuthentication(u, p string, matched bool) ResourceOwnerAuthentication {
	return func(username, password string) (bool, error) {
		if username == u && password == p {
			return matched, nil
		}
		return false, nil
	}
}

///////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// Resource Owner Credentials Flow ///////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

type resourceOwnerFlowTestCase struct {
	tokenGrantTestCase
	authentication ResourceOwnerAuthentication
}

func TestResourceOwnerPasswordCredentialsFlow_Generate(t *testing.T) {
	tests := []resourceOwnerFlowTestCase{
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "유저 아이디 미입력시 ErrInvalidRequest 발생",
				store: &mockStore{},
				request: &pkg.TokenRequest{
					Username: "",
				},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "유저 패스워드 미입력시 ErrInvalidRequest 발생",
				store: &mockStore{},
				request: &pkg.TokenRequest{
					Username: testUsername,
					Password: "",
				},
				expect: tokenGrantExpected{
					err: ErrInvalidRequest,
				},
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "회원 인증에 실패시 ErrUnauthorized 발생",
				store: &mockStore{},
				request: &pkg.TokenRequest{
					Username: testUsername,
					Password: testPassword,
				},
				expect: tokenGrantExpected{
					err: ErrUnauthorized,
				},
			},
			authentication: fixedAuthentication(testUsername, testPassword, false),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:        "클라이언트가 공개 클라이언트인 경우 리플레시 토큰은 생성하지 않음",
				store:       &mockStore{},
				idGenerator: fixedTokenIDGenerator(testTokenValue),
				client: &client.Client{
					ID:     testClientID,
					Type:   pkg.ClientTypePublic,
					Scopes: testutils.ScopeList("scope_1", "scope_2", "scope_3"),
				},
				request: &pkg.TokenRequest{
					Username: testUsername,
					Password: testPassword,
					Scope:    "scope_1 scope_2",
				},
				expect: tokenGrantExpected{
					savedToken: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Scopes:   testutils.ScopeList("scope_1", "scope_2"), // 요청한 리스트만 부여 받아야 한다.
						Username: testUsername,
					},
					savedRefreshToken: nil,
				},
			},
			authentication: fixedAuthentication(testUsername, testPassword, true),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:        "클라이언트가 공개 클라이언트가 아닌 경우 리플래시 토큰을 생성한다.",
				store:       &mockStore{},
				idGenerator: fixedTokenIDGenerator(testTokenValue),
				client: &client.Client{
					ID:     testClientID,
					Type:   pkg.ClientTypeConfidential,
					Scopes: testutils.ScopeList("scope_1", "scope_2", "scope_3"),
				},
				request: &pkg.TokenRequest{
					Username: testUsername,
					Password: testPassword,
					Scope:    "scope_1 scope_2",
				},
				expect: tokenGrantExpected{
					savedToken: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Scopes:   testutils.ScopeList("scope_1", "scope_2"), // 요청한 리스트만 부여 받아야 한다.
						Username: testUsername,
					},
					savedRefreshToken: &RefreshToken{
						Value: testTokenValue,
						Token: &Token{
							Value:    testTokenValue,
							ClientID: testClientID,
							Scopes:   testutils.ScopeList("scope_1", "scope_2"), // 요청한 리스트만 부여 받아야 한다.
							Username: testUsername,
						},
					},
				},
			},
			authentication: fixedAuthentication(testUsername, testPassword, true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewResourceOwnerPasswordCredentialsFlow(tc.authentication, tc.store)
			srv.IDGenerator = tc.idGenerator

			_, _, err := srv.Generate(tc.client, tc.request)
			tokenGrantAssert(t, tc.tokenGrantTestCase, err)
		})
	}
}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Refresh Token Flow //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////

func TestRefreshFlow_Generate(t *testing.T) {
	tests := []tokenGrantTestCase{
		{
			name:  "리플레시 토큰이 입력 되지 않았을 경우 ErrInvalidRequest 발생",
			store: &mockStore{},
			request: &pkg.TokenRequest{
				RefreshToken: "",
			},
			expect: tokenGrantExpected{
				err: ErrInvalidRequest,
			},
		},
		{
			name: "리플레시 토큰을 찾을 수 없을 경우 ErrTokenCannotGrant 발생",
			store: &mockStore{
				findRefreshTokenByValue: func(v string) (*RefreshToken, error) {
					if v == testRefreshTokenValue {
						return nil, ErrRefreshTokenNotFound
					}
					return nil, nil
				},
			},
			request: &pkg.TokenRequest{
				RefreshToken: testRefreshTokenValue,
			},
			expect: tokenGrantExpected{
				err: ErrTokenCannotGrant,
			},
		},
		{
			name: "리플레시 토큰의 클라이언트가 요청한 클라이언트와 다를 경우 ErrUnauthorized 발생",
			store: &mockStore{
				findRefreshTokenByValue: func(v string) (*RefreshToken, error) {
					token := &Token{
						ClientID: testClientID,
					}
					refreshToken := &RefreshToken{
						Token: token,
					}
					if v == testRefreshTokenValue {
						return refreshToken, nil
					}
					return nil, ErrRefreshTokenNotFound
				},
			},
			client: &client.Client{
				ID: 2,
			},
			request: &pkg.TokenRequest{
				RefreshToken: testRefreshTokenValue,
			},
			expect: tokenGrantExpected{
				err: ErrUnauthorized,
			},
		},
		{
			name: "리플레시 토큰이 만료 되었을 경우 ErrTokenCannotGrant 발생",
			store: &mockStore{
				findRefreshTokenByValue: func(v string) (*RefreshToken, error) {
					token := &Token{
						ClientID: testClientID,
						Range: Range{
							ExpiredAt: time.Now().Add(-1 * time.Second), // 1초 전에 만료
						},
					}
					refreshToken := &RefreshToken{
						Token: token,
					}
					if v == testRefreshTokenValue {
						return refreshToken, nil
					}
					return nil, ErrRefreshTokenNotFound
				},
			},
			client: &client.Client{
				ID: testClientID,
			},
			request: &pkg.TokenRequest{
				RefreshToken: testRefreshTokenValue,
			},
			expect: tokenGrantExpected{
				err: ErrTokenCannotGrant,
			},
		},
		{
			name:        "사용자가 스코프를 요청하지 않았을 경우 기존 토큰의 스코프를 모두 부여 받는다.",
			idGenerator: fixedTokenIDGenerator(testTokenValue),
			store: &mockStore{
				findRefreshTokenByValue: func(v string) (*RefreshToken, error) {
					token := &Token{
						ID:       testTokenID,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList(testScopeArray...),
					}
					refreshToken := &RefreshToken{
						ID:    testRefreshTokenID,
						Token: token,
						Range: Range{
							ExpiredAt: time.Now().Add(1 * time.Second),
						},
					}
					if v == testRefreshTokenValue {
						return refreshToken, nil
					}
					return nil, ErrRefreshTokenNotFound
				},
			},
			client: &client.Client{
				ID:     testClientID,
				Scopes: testutils.ScopeList(testScopeArray...),
			},
			request: &pkg.TokenRequest{
				RefreshToken: testRefreshTokenValue,
				Scope:        "",
			},
			expect: tokenGrantExpected{
				deletedRefreshToken: &RefreshToken{
					ID: testRefreshTokenID,
				},
				deletedToken: &Token{
					ID: testTokenID,
				},
				savedToken: &Token{
					Value:    testTokenValue,
					ClientID: testClientID,
					Username: testUsername,
					Scopes:   testutils.ScopeList(testScopeArray...),
				},
				savedRefreshToken: &RefreshToken{
					Value: testTokenValue,
					Token: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList(testScopeArray...),
					},
				},
			},
		},
		{
			name:        "사용자가 스코프를 요청하였을 경우 요청된 스코프를 부여 받는다.",
			idGenerator: fixedTokenIDGenerator(testTokenValue),
			store: &mockStore{
				findRefreshTokenByValue: func(v string) (*RefreshToken, error) {
					token := &Token{
						ID:       testTokenID,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList(testScopeArray...),
					}
					refreshToken := &RefreshToken{
						ID:    testRefreshTokenID,
						Token: token,
						Range: Range{
							ExpiredAt: time.Now().Add(1 * time.Second),
						},
					}
					if v == testRefreshTokenValue {
						return refreshToken, nil
					}
					return nil, ErrRefreshTokenNotFound
				},
			},
			client: &client.Client{
				ID:     testClientID,
				Scopes: testutils.ScopeList(testScopeArray...),
			},
			request: &pkg.TokenRequest{
				RefreshToken: testRefreshTokenValue,
				Scope:        "scope_1 scope_2",
			},
			expect: tokenGrantExpected{
				deletedRefreshToken: &RefreshToken{
					ID: testRefreshTokenID,
				},
				deletedToken: &Token{
					ID: testTokenID,
				},
				savedToken: &Token{
					Value:    testTokenValue,
					ClientID: testClientID,
					Username: testUsername,
					Scopes:   testutils.ScopeList("scope_1", "scope_2"),
				},
				savedRefreshToken: &RefreshToken{
					Value: testTokenValue,
					Token: &Token{
						Value:    testTokenValue,
						ClientID: testClientID,
						Username: testUsername,
						Scopes:   testutils.ScopeList("scope_1", "scope_2"),
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewRefreshFlow(tc.store)
			srv.IDGenerator = tc.idGenerator

			_, _, err := srv.Generate(tc.client, tc.request)
			tokenGrantAssert(t, tc, err)
		})
	}
}

/////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Client Credentials Flow ////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

func TestClientCredentialsFlow_Generate(t *testing.T) {
	tests := []tokenGrantTestCase{
		{
			name:  "클라이언트가 공개 클라이언트인 경우 ErrUnauthorized 발생",
			store: &mockStore{},
			client: &client.Client{
				Type: pkg.ClientTypePublic,
			},
			expect: tokenGrantExpected{
				err: ErrUnauthorized,
			},
		},
		{
			name:        "클라이언트 토큰 부여는 리플레시 토큰을 생성하지 않음",
			store:       &mockStore{},
			idGenerator: fixedTokenIDGenerator(testTokenValue),
			client: &client.Client{
				ID:     testClientID,
				Type:   pkg.ClientTypeConfidential,
				Scopes: testutils.ScopeList(testScopeArray...),
			},
			request: &pkg.TokenRequest{
				Scope: "scope_1 scope_2",
			},
			expect: tokenGrantExpected{
				savedToken: &Token{
					Value:    testTokenValue,
					Username: "",
					ClientID: testClientID,
					Scopes:   testutils.ScopeList("scope_1", "scope_2"), // 요청한 스코프만 부여 받음
				},
				savedRefreshToken: nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewClientCredentialsFlow(tc.store)
			srv.IDGenerator = tc.idGenerator

			_, _, err := srv.Generate(tc.client, tc.request)
			tokenGrantAssert(t, tc, err)
		})
	}
}

/////////////////////////////////////////////////////////////////////
//////////////////////////////// 검증 ////////////////////////////////
/////////////////////////////////////////////////////////////////////

func tokenGrantAssert(t *testing.T, tc tokenGrantTestCase, err error) {
	tokenAssert := func(expected *Token, actual *Token) {
		assert.Equal(t, expected.Value, actual.Value)
		assert.Equal(t, expected.ClientID, actual.ClientID)
		assert.Equal(t, expected.Scopes, actual.Scopes)
		assert.Equal(t, expected.Username, actual.Username)
	}
	if tc.expect.err != nil {
		assert.ErrorIs(t, tc.expect.err, err)
	} else {
		assert.Nil(t, err)
	}
	if tc.expect.savedToken != nil {
		if assert.NotNil(t, tc.store.savedToken) {
			tokenAssert(tc.expect.savedToken, tc.store.savedToken)
		}
	} else {
		assert.Nil(t, tc.store.savedToken)
	}
	if tc.expect.savedRefreshToken != nil {
		if assert.NotNil(t, tc.store.savedRefresh) {
			assert.Equal(t, tc.expect.savedRefreshToken.Value, tc.store.savedRefresh.Value)
			if assert.NotNil(t, tc.store.savedRefresh.Token) {
				tokenAssert(tc.expect.savedToken, tc.store.savedToken)
			}
		}
	} else {
		assert.Nil(t, tc.store.savedRefresh)
	}
	if tc.expect.deletedToken != nil {
		if assert.NotNil(t, tc.store.deletedToken) {
			assert.Equal(t, tc.expect.deletedToken.ID, tc.store.deletedToken.ID)
		}
	} else {
		assert.Nil(t, tc.store.deletedToken)
	}
	if tc.expect.deletedRefreshToken != nil {
		if assert.NotNil(t, tc.store.deletedRefresh) {
			assert.Equal(t, tc.expect.deletedRefreshToken.ID, tc.store.deletedRefresh.ID)
		}
	} else {
		assert.Nil(t, tc.store.deletedRefresh)
	}
}
