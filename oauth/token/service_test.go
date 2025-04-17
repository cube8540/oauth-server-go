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

type authCodeFlowTestCase struct {
	name     string
	store    *mockStore
	consumer AuthCodeConsume
	gen      IDGenerator
	c        *client.Client
	r        *pkg.TokenRequest
	expect   authCodeFlowExpect
}

type authCodeFlowExpect struct {
	token        func(t *Token) bool
	refresh      func(t *RefreshToken) bool
	savedToken   func(t *Token) bool
	savedRefresh func(t *RefreshToken) bool
	err          error
}

func TestAuthorizationCodeFlow_Generate(t *testing.T) {
	tests := []authCodeFlowTestCase{
		{
			name: "인가 코드의 클라이언트와 요청 클라이언트가 다른 경우",
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID: 2,
			}),
			c: &client.Client{ID: 1},
			r: &pkg.TokenRequest{
				Code: "code",
			},
			expect: authCodeFlowExpect{
				err: ErrUnauthorized,
			},
		},
		{
			name: "인가 코드가 만료 되었을 경우",
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:  1,
				ExpiredAt: time.Now().Add(-1 * time.Second),
			}),
			c:      &client.Client{ID: 1},
			r:      &pkg.TokenRequest{Code: "code"},
			expect: authCodeFlowExpect{err: ErrTokenCannotGrant},
		},
		{
			name: "PKCE 검증에 실패 했을 경우",
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
			}),
			c: &client.Client{ID: 1},
			r: &pkg.TokenRequest{
				Code:         "code",
				CodeVerifier: "wrong verifier",
			},
			expect: authCodeFlowExpect{err: ErrInvalidRequest},
		},
		{
			name: "요청 클라이언트가 공개 클라이언트인 경우",
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
			}),
			store: &mockStore{},
			gen: func() string {
				return "TEST_TOKEN_ID"
			},
			c: &client.Client{
				ID:   1,
				Type: pkg.ClientTypePublic,
			},
			r: &pkg.TokenRequest{
				Code:         "code",
				CodeVerifier: "abcde",
			},
			expect: authCodeFlowExpect{
				token: func(t *Token) bool {
					return t.Value == "TEST_TOKEN_ID" && t.ClientID == 1
				},
				savedToken: func(t *Token) bool {
					return t.Value == "TEST_TOKEN_ID" && t.ClientID == 1
				},
			},
		},
		{
			name: "요청 클라이언트가 공개 클라이언트가 아닌 경우",
			consumer: authorizationCodeConsumer("code", &code.AuthorizationCode{
				ClientID:            1,
				ExpiredAt:           time.Now().Add(1 * time.Second),
				CodeChallengeMethod: pkg.ChallengePlan,
				CodeChallenge:       "abcde",
			}),
			store: &mockStore{},
			gen: func() string {
				return "TEST_TOKEN_ID"
			},
			c: &client.Client{
				ID:   1,
				Type: pkg.ClientTypeConfidential,
			},
			r: &pkg.TokenRequest{
				Code:         "code",
				CodeVerifier: "abcde",
			},
			expect: authCodeFlowExpect{
				token: func(t *Token) bool {
					return t.Value == "TEST_TOKEN_ID" && t.ClientID == 1
				},
				savedToken: func(t *Token) bool {
					return t.Value == "TEST_TOKEN_ID" && t.ClientID == 1
				},
				refresh: func(t *RefreshToken) bool {
					return t.Value == "TEST_TOKEN_ID" && t.Token.Value == "TEST_TOKEN_ID"
				},
				savedRefresh: func(t *RefreshToken) bool {
					return t.Value == "TEST_TOKEN_ID" && t.Token.Value == "TEST_TOKEN_ID"
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewAuthorizationCodeFlow(tc.store, tc.consumer)
			srv.IDGenerator = tc.gen

			token, refresh, err := srv.Generate(tc.c, tc.r)
			if token != nil && !tc.expect.token(token) {
				t.Errorf("반환 받은 토큰이 기대 하였던 것과 다릅니다.\n 실제:%+#v", token)
			}
			if refresh != nil && !tc.expect.refresh(refresh) {
				t.Errorf("반환 받은 리플레시 토큰이 기대 하였던 것과 다릅니다.\n실제:%+#v", refresh)
			}
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
