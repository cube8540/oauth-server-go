package token

import (
	"errors"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"slices"
	"testing"
	"time"
)

type mockStore struct {
	findAccessTokenByValue  func(v string) (*Token, error)
	findRefreshTokenByValue func(v string) (*RefreshToken, error)
	refresh                 func(oldRefreshToken *RefreshToken, newToken *Token, fn func(t *Token) *RefreshToken) error

	savedToken   []*Token
	savedRefresh []*RefreshToken

	deletedToken   []*Token
	deletedRefresh []*RefreshToken
}

func (m *mockStore) Save(t *Token, fn func(t *Token) *RefreshToken) error {
	m.savedToken = append(m.savedToken, t)
	if refresh := fn(t); refresh != nil {
		m.savedRefresh = append(m.savedRefresh, refresh)
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
	m.deletedRefresh = append(m.deletedRefresh, oldRefreshToken)
	m.deletedToken = append(m.deletedToken, oldRefreshToken.Token)
	m.savedToken = append(m.savedToken, newToken)
	if refresh := fn(newToken); refresh != nil {
		m.savedRefresh = append(m.savedRefresh, refresh)
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

func scopeList(c ...string) []client.Scope {
	var scopes []client.Scope
	for _, v := range c {
		scopes = append(scopes, client.Scope{Code: v})
	}
	return scopes
}

func expectToken(id string, c uint, scopes []client.Scope) func(t *Token) bool {
	return func(t *Token) bool {
		return t.Value == id && t.ClientID == c && slices.EqualFunc(t.Scopes, scopes, func(s1, s2 client.Scope) bool {
			return s1.Code == s2.Code
		})
	}
}

func expectRefresh(id, token string) func(t *RefreshToken) bool {
	return func(t *RefreshToken) bool {
		return t.Value == id && t.Token.Value == token
	}
}

type tokenGrantedExpect struct {
	token         func(t *Token) bool
	refresh       func(t *RefreshToken) bool
	savedToken    func(t *Token) bool
	savedRefresh  func(t *RefreshToken) bool
	deleteToken   func(t *Token) bool
	deleteRefresh func(t *RefreshToken) bool
	err           error
}

type tokenGrantTestCase struct {
	name   string
	store  *mockStore
	c      *client.Client
	r      *pkg.TokenRequest
	expect tokenGrantedExpect
}

type authCodeFlowTestCase struct {
	tokenGrantTestCase
	consumer AuthCodeConsume
	gen      IDGenerator
}

func TestAuthorizationCodeFlow_Generate(t *testing.T) {
	tests := []authCodeFlowTestCase{
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name: "인가 코드의 클라이언트와 요청 클라이언트가 다른 경우",
				c:    &client.Client{ID: 1},
				r: &pkg.TokenRequest{
					Code: "code",
				},
				expect: tokenGrantedExpect{
					err: ErrUnauthorized,
				},
			},
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID: 2,
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:   "인가 코드가 만료 되었을 경우",
				c:      &client.Client{ID: 1},
				r:      &pkg.TokenRequest{Code: "code"},
				expect: tokenGrantedExpect{err: ErrTokenCannotGrant},
			},
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:  1,
				ExpiredAt: time.Now().Add(-1 * time.Second),
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name: "PKCE 검증에 실패 했을 경우",
				c:    &client.Client{ID: 1},
				r: &pkg.TokenRequest{
					Code:         "code",
					CodeVerifier: "wrong verifier",
				},
				expect: tokenGrantedExpect{err: ErrInvalidRequest},
			},
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
			}),
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "요청 클라이언트가 공개 클라이언트인 경우",
				store: &mockStore{},
				c: &client.Client{
					ID:   1,
					Type: pkg.ClientTypePublic,
				},
				r: &pkg.TokenRequest{
					Code:         "code",
					CodeVerifier: "abcde",
				},
				expect: tokenGrantedExpect{
					savedToken: expectToken("TEST_TOKEN_ID", 1, scopeList("scope_1", "scope_2", "scope_3")),
				},
			},
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
				Scopes:              scopeList("scope_1", "scope_2", "scope_3"),
			}),
			gen: func() string {
				return "TEST_TOKEN_ID"
			},
		},
		{
			tokenGrantTestCase: tokenGrantTestCase{
				name:  "요청 클라이언트가 공개 클라이언트가 아닌 경우",
				store: &mockStore{},
				c: &client.Client{
					ID:   1,
					Type: pkg.ClientTypeConfidential,
				},
				r: &pkg.TokenRequest{
					Code:         "code",
					CodeVerifier: "abcde",
				},
				expect: tokenGrantedExpect{
					savedToken:   expectToken("TEST_TOKEN_ID", 1, scopeList("scope_1", "scope_2", "scope_3")),
					savedRefresh: expectRefresh("TEST_TOKEN_ID", "TEST_TOKEN_ID"),
				},
			},
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
				Scopes:              scopeList("scope_1", "scope_2", "scope_3"),
			}),
			gen: func() string {
				return "TEST_TOKEN_ID"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewAuthorizationCodeFlow(tc.store, tc.consumer)
			srv.IDGenerator = tc.gen

			_, _, err := srv.Generate(tc.c, tc.r)
			if !errors.Is(err, tc.expect.err) {
				t.Errorf("발생한 에러가 기대 하였던 것과 다릅니다.\n기대:%v\n실제:%v", tc.expect.err, err)
			}
			if tc.expect.savedToken != nil && !slices.ContainsFunc(tc.store.savedToken, tc.expect.savedToken) {
				t.Errorf("예상 하던 토큰들이 저장 되지 않았습니다.\n실제:%+#v", tc.store.savedToken)
			}
			if tc.expect.savedRefresh != nil && !slices.ContainsFunc(tc.store.savedRefresh, tc.expect.savedRefresh) {
				t.Errorf("예상 하던 리플레시 토큰들이 저장 되지 않았습니다.\n실제:%+#v", tc.store.savedRefresh)
			}
		})
	}
}
