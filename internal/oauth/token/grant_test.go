package token

import (
	"github.com/stretchr/testify/assert"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/pkg/period"
	"testing"
	"time"
)

// 토큰 발급 테스트에서 사용할 상수
const (
	// testAccessTokenValue 테스트용으로 사용될 엑세스 토큰의 토큰값
	testAccessTokenValue = "test_access_token"
	// testRefreshTokenValue 테스트용으로 사용될 리플레시 토큰의 토큰값
	testRefreshTokenValue = "test_refresh_token"
	// testStoredRefreshTokenValue 테스트용으로 사용될 이미 저장소에 저장되어 있는 리플레시 토큰값
	testStoredRefreshTokenValue = "test_stored_refresh_token"

	// testClientID 테스트용으로 사용될 클라이언트의 아이디
	testClientID = "test_client_id"
	// testRedirectURI 테스트용으로 사용될 리다이렉트 URI
	// 테스트 클라이언트에 등록되어야 한다.
	testRedirectURI = "http://localhost:8080"

	testUsername = "test_username"
	testPassword = "<PASSWORD>"
)

// 토큰 발급 테스트에서 사용할 상수
var (
	testScopeArray = []string{"scope_1", "scope_2", "scope_3"}

	testStoredStart = time.Now().Add(-time.Hour)
	testStoredEnd   = time.Now().Add(time.Hour)
)

// generateTestAccessToken 테스트용으로 사용될 엑세스 토큰 발급 함수
// [token.GenerateToken] 함수의 구현채로 사용된다.
func generateTestAccessToken() string {
	return testAccessTokenValue
}

// generateTestRefreshToken 테스트용으로 사용될 리플레시 토큰 발급 함수
// [token.GenerateToken] 함수의 구현채로 사용된다.
func generateTestRefreshToken() string {
	return testRefreshTokenValue
}

// generateStoredRefreshToken 테스트용으로 사용될 이미 저장된 리플레시 토큰 발급 함수
// [token.GenerateToken] 함수의 구현채로 사용된다.
func generateStoredRefreshToken() string {
	return testStoredRefreshTokenValue
}

func newClient(clientID string, t client.Type, scope []string) *client.Client {
	c := client.New(clientID, "", "", t)
	for _, s := range scope {
		c.AddScope(s)
	}
	return c
}

// grantTestCase 토큰 발행 테스트 케이스
type grantTestCase struct {
	// name 테스트명
	name string

	// client 토큰 발급을 요청한 클라이언트
	client *client.Client

	// accessTokenGenerator 엑세스 토큰 발급 함수
	accessTokenGenerator GenerateToken

	// request 토큰 발행 요청
	request *Request
}

// grantExceptCase 토큰 발급 완료시 예상되는 결과값
type grantExceptCase struct {
	// err 에러 발생을 예상 했을떄 발생할 에러를 지정한다.
	err error

	// assertAccessToken 생성된 엑세스 토큰의 검증을 하는 함수
	assertAccessToken func(t *testing.T, accessToken *AccessToken)

	// assertRefreshToken 생성된 리플레시 토큰의 검증을 하는 함수
	assertRefreshToken func(t *testing.T, refreshToken *RefreshToken)
}

// 인가 코드 승인 방식 테스트에서 사용할 상수 모음
const (
	// testAuthorizationCodeValue 테스트용으로 사용할 인가 코드
	testAuthorizationCodeValue = "test_authorization_code"
	// testCodeChallenge 테스트용으로 사용할 PKCE 검증값
	// 토큰 발급에서 PKCE 검증값의 해싱 방식을 정할 이유가 없음으로 간단함을 위해 PLAN을 사용
	testCodeChallenge = "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2"
)

// generateTestAuthorizationCode 테스트용으로 사용될 인가 코드 발급 함수
// [authorization.GenerateCode] 함수의 구현체로 사용된다.
func generateTestAuthorizationCode() string {
	return testAuthorizationCodeValue
}

func newAuthorizationRequest(redirect, codeChallenge string, scopes []string) *authorization.Request {
	return &authorization.Request{
		Username:            testUsername,
		Redirect:            redirect,
		Scopes:              scope.Join(scopes),
		CodeChallenge:       authorization.Challenge(codeChallenge),
		CodeChallengeMethod: authorization.ChallengePlan,
	}
}

// authorizationCodeGrantTestCase 인가 코드 승인 방식 테스트 케이스
type authorizationCodeGrantTestCase struct {
	grantTestCase
	grantExceptCase

	// retrieveAuthorizationCode 인가 코드 검색 함수
	retrieveAuthorizationCode RetrieveAuthorizationCode

	// refreshTokenGenerator 리플레시 토큰 발급 함수
	refreshTokenGenerator GenerateToken
}

func TestAuthorizationCodeGrant_GenerateToken(t *testing.T) {
	tests := []authorizationCodeGrantTestCase{
		{
			grantTestCase: grantTestCase{
				name: "인가 코드 누락시 ErrMissingParameter 발생",
				request: &Request{
					Code: "",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrMissingParameter,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "유효하지 않은 인가 코드시 ErrInvalidRequest 발생",
				request: &Request{
					Code: "wrong code",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidRequest,
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				return nil, false
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "만료된 인가 코드시 ErrExpiredResource 발생",
				request: &Request{
					Code: "wrong code",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrExpiredResource,
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				return &authorization.Code{Range: period.New(time.Duration(-1))}, true
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "클라이언트 ID 불일치시 ErrInvalidClient 발생",
				request: &Request{
					Code: testAuthorizationCodeValue,
				},
				client: newClient("wrong client id", client.TypeConfidential, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidClient,
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				return authorization.NewCode(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAuthorizationCode), true
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "리다이렉트 URI 불일치시 ErrInvalidRequest 발생",
				request: &Request{
					Code:     testAuthorizationCodeValue,
					Redirect: "wrong redirect uri",
				},
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidRequest,
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				c := authorization.NewCode(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAuthorizationCode)
				r := newAuthorizationRequest(testRedirectURI, testCodeChallenge, testScopeArray)
				_ = c.CopyFrom(r)
				return c, true
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "PKCE 검증 실패시 ErrInvalidRequest 발생",
				request: &Request{
					Code:         testAuthorizationCodeValue,
					Redirect:     testRedirectURI,
					CodeVerifier: "wrong code verifier",
				},
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidRequest,
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				c := authorization.NewCode(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAuthorizationCode)
				r := newAuthorizationRequest(testRedirectURI, testCodeChallenge, testScopeArray)
				_ = c.CopyFrom(r)
				return c, true
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "액세스 토큰에 인가 코드의 정보가 올바르게 설정됨",
				request: &Request{
					Code:         testAuthorizationCodeValue,
					Redirect:     testRedirectURI,
					CodeVerifier: testCodeChallenge,
				},
				client:               newClient(testClientID, client.TypePublic, testScopeArray),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.NotNil(t, accessToken)
					assert.Equal(t, testClientID, accessToken.Client().Id())
					assert.Equal(t, testUsername, accessToken.Username())
					assert.Equal(t, testScopeArray, accessToken.Scopes())
				},
			},
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				c := authorization.NewCode(newClient(testClientID, client.TypePublic, testScopeArray), generateTestAuthorizationCode)
				r := newAuthorizationRequest(testRedirectURI, testCodeChallenge, testScopeArray)
				_ = c.CopyFrom(r)
				return c, true
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "비공개 클라이언트의 경우 리프레시 토큰 생성",
				request: &Request{
					Code:         testAuthorizationCodeValue,
					Redirect:     testRedirectURI,
					CodeVerifier: testCodeChallenge,
				},
				client:               newClient(testClientID, client.TypeConfidential, testScopeArray),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertRefreshToken: func(t *testing.T, refreshToken *RefreshToken) {
					assert.NotNil(t, refreshToken)
				},
			},
			refreshTokenGenerator: generateTestRefreshToken,
			retrieveAuthorizationCode: func(code string) (*authorization.Code, bool) {
				c := authorization.NewCode(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAuthorizationCode)
				r := newAuthorizationRequest(testRedirectURI, testCodeChallenge, testScopeArray)
				_ = c.CopyFrom(r)
				return c, true
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granter := NewAuthorizationCodeGrant(tc.accessTokenGenerator, tc.refreshTokenGenerator, tc.retrieveAuthorizationCode)
			accessToken, refreshToken, err := granter.GenerateToken(tc.client, tc.request)
			if tc.grantExceptCase.err != nil {
				assert.ErrorIs(t, err, tc.grantExceptCase.err)
			} else {
				assert.Nil(t, err)
				if tc.assertAccessToken != nil {
					tc.assertAccessToken(t, accessToken)
				}
				if tc.assertRefreshToken != nil {
					tc.assertRefreshToken(t, refreshToken)
				}
			}
		})
	}
}

// implicitGrantTestCase 암묵적 승인 방식의 테스트 케이스
type implicitGrantTestCase struct {
	grantTestCase
	grantExceptCase
}

func TestImplicitGrant_GenerateToken(t *testing.T) {
	tests := []implicitGrantTestCase{
		{
			grantTestCase: grantTestCase{
				name: "유효하지 않은 스코프 요청시 ErrInvalidScope 발생",
				request: &Request{
					Scope: "scope_1 scope_2 scope_3 wrong_scope",
				},
				client: newClient(testClientID, client.TypePublic, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidScope,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "유효하지 않은 리다이렉트 URI시 ErrInvalidRequest 발생",
				request: &Request{
					Scope:    scope.Join(testScopeArray),
					Redirect: "wrong redirect uri",
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidRequest,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "액세스 토큰에 자원 소유자 정보와 스코프가 올바르게 설정됨",
				request: &Request{
					Scope:    scope.Join(testScopeArray),
					Redirect: testRedirectURI,
					Username: testUsername,
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.NotNil(t, accessToken)
					assert.Equal(t, testClientID, accessToken.Client().Id())
					assert.Equal(t, testUsername, accessToken.Username())
					assert.Equal(t, testScopeArray, accessToken.Scopes())
				},
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "리프레시 토큰이 생성되지 않음",
				request: &Request{
					Scope:    scope.Join(testScopeArray),
					Redirect: testRedirectURI,
					Username: testUsername,
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertRefreshToken: func(t *testing.T, refreshToken *RefreshToken) {
					assert.Nil(t, refreshToken)
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granter := ImplicitGrant{accessTokenGenerator: generateTestAccessToken}
			accessToken, err := granter.GenerateToken(tc.client, tc.request)
			if tc.grantExceptCase.err != nil {
				assert.ErrorIs(t, err, tc.grantExceptCase.err)
			} else {
				assert.Nil(t, err)
				if tc.assertAccessToken != nil {
					tc.assertAccessToken(t, accessToken)
				}
			}
		})
	}
}

// authenticateResourceOwner 테스트로 사용할 자원 소유자 인증 함수
// 단순히 아이디와 패스워드를 받아 모두 일치하는지 여부를 반환한다.
func authenticateResourceOwner(username, password string) func(username, password string) (bool, error) {
	return func(u, p string) (bool, error) {
		return username == u && password == p, nil
	}
}

// resourceOwnerPasswordCredentialsGrantTestCase 자원 소유자 자격 증명 방식 테스트 케이스
type resourceOwnerPasswordCredentialsGrantTestCase struct {
	grantTestCase
	grantExceptCase

	// authenticate 자원 소유자 인증 함수
	authenticate AuthenticateResourceOwner

	// refreshTokenGenerator 리플레시 토큰 발급 함수
	refreshTokenGenerator GenerateToken
}

func TestResourceOwnerPasswordCredentialsGrant_GenerateToken(t *testing.T) {
	tests := []resourceOwnerPasswordCredentialsGrantTestCase{
		{
			grantTestCase: grantTestCase{
				name: "아이디 누락시 ErrMissingParameter 발생",
				request: &Request{
					Username: "",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrMissingParameter,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "비밀번호 누락시 ErrMissingParameter 발생",
				request: &Request{
					Username: testUsername,
					Password: "",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrMissingParameter,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "인증 실패시 ErrUnauthorized 발생",
				request: &Request{
					Username: testUsername,
					Password: "wrong password",
					Redirect: testRedirectURI,
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrUnauthorized,
			},
			authenticate: authenticateResourceOwner(testUsername, testPassword),
		},
		{
			grantTestCase: grantTestCase{
				name: "유효하지 않은 스코프 요청시 ErrInvalidScope 발생",
				request: &Request{
					Username: testUsername,
					Password: testPassword,
					Redirect: testRedirectURI,
					Scope:    "scope_1 scope_2 scope_3 wrong_scope",
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidScope,
			},
			authenticate: authenticateResourceOwner(testUsername, testPassword),
		},
		{
			grantTestCase: grantTestCase{
				name: "액세스 토큰에 자원 소유자 정보와 스코프가 올바르게 설정됨",
				request: &Request{
					Username: testUsername,
					Password: testPassword,
					Redirect: testRedirectURI,
					Scope:    scope.Join(testScopeArray),
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypePublic, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.NotNil(t, accessToken)
					assert.Equal(t, testClientID, accessToken.Client().Id())
					assert.Equal(t, testUsername, accessToken.Username())
					assert.Equal(t, testScopeArray, accessToken.Scopes())
				},
			},
			authenticate: authenticateResourceOwner(testUsername, testPassword),
		},
		{
			grantTestCase: grantTestCase{
				name: "비공개 클라이언트의 경우 리프레시 토큰 생성",
				request: &Request{
					Username: testUsername,
					Password: testPassword,
					Redirect: testRedirectURI,
					Scope:    scope.Join(testScopeArray),
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypeConfidential, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertRefreshToken: func(t *testing.T, refreshToken *RefreshToken) {
					assert.NotNil(t, refreshToken)
				},
			},
			authenticate:          authenticateResourceOwner(testUsername, testPassword),
			refreshTokenGenerator: generateTestRefreshToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granter := ResourceOwnerPasswordCredentialsGrant{
				authentication:        tc.authenticate,
				accessTokenGenerator:  tc.accessTokenGenerator,
				refreshTokenGenerator: tc.refreshTokenGenerator,
			}

			accessToken, refreshToken, err := granter.GenerateToken(tc.client, tc.request)
			if tc.grantExceptCase.err != nil {
				assert.ErrorIs(t, err, tc.grantExceptCase.err)
			} else {
				assert.Nil(t, err)
				if tc.assertAccessToken != nil {
					tc.assertAccessToken(t, accessToken)
				}
				if tc.assertRefreshToken != nil {
					tc.assertRefreshToken(t, refreshToken)
				}
			}
		})
	}
}

// clientCredentialsGrantTestCase 클라이언트 자격 증명 방식 테스트 케이스
type clientCredentialsGrantTestCase struct {
	grantTestCase
	grantExceptCase
}

func TestClientCredentialsGrant_GenerateToken(t *testing.T) {
	tests := []clientCredentialsGrantTestCase{
		{
			grantTestCase: grantTestCase{
				name:   "공개 클라이언트 요청시 ErrInvalidClient 발생",
				client: newClient(testClientID, client.TypePublic, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidClient,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "유효하지 않은 스코프 요청시 ErrInvalidScope 발생",
				request: &Request{
					Scope: "scope_1 scope_2 scope_3 wrong_scope",
				},
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidScope,
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "액세스 토큰에 클라이언트 정보와 스코프가 올바르게 설정됨",
				request: &Request{
					Scope:    scope.Join(testScopeArray),
					Redirect: testRedirectURI,
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypeConfidential, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.NotNil(t, accessToken)
					assert.Equal(t, testClientID, accessToken.Client().Id())
					assert.Equal(t, testScopeArray, accessToken.Scopes())
				},
			},
		},
		{
			grantTestCase: grantTestCase{
				name: "액세스 토큰의 자원 소유자 식별자가 공백으로 설정됨",
				request: &Request{
					Scope:    scope.Join(testScopeArray),
					Redirect: testRedirectURI,
				},
				client: func() *client.Client {
					c := newClient(testClientID, client.TypeConfidential, testScopeArray)
					c.AddRedirect(testRedirectURI)
					return c
				}(),
				accessTokenGenerator: generateTestAccessToken,
			},
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.NotNil(t, accessToken)
					assert.Equal(t, "", accessToken.Username())
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granter := ClientCredentialsGrant{accessTokenGenerator: tc.accessTokenGenerator}
			accessToken, err := granter.GenerateToken(tc.client, tc.request)
			if tc.grantExceptCase.err != nil {
				assert.ErrorIs(t, err, tc.grantExceptCase.err)
			} else {
				assert.Nil(t, err)
				if tc.assertAccessToken != nil {
					tc.assertAccessToken(t, accessToken)
				}
			}
		})
	}
}

// refreshTokenGrantTestCase 리플레시 토큰 승인 방식 테스트 케이스
type refreshTokenGrantTestCase struct {
	grantTestCase
	grantExceptCase

	refreshTokenGenerator GenerateToken
	refreshTokenRetriever RetrieveRefreshToken

	rotation bool
}

// retrieveRefreshToken 테스트용으로 사용할 리플레시 토큰 검색 함수
func retrieveRefreshToken(token string, refreshToken *RefreshToken) func(token string) (*RefreshToken, bool) {
	return func(r string) (*RefreshToken, bool) {
		if r == token {
			return refreshToken, true
		} else {
			return nil, false
		}
	}
}

func TestRefreshTokenGrant_GenerateToken(t *testing.T) {
	tests := []refreshTokenGrantTestCase{
		{
			grantTestCase: grantTestCase{
				name: "리프레시 토큰 누락시 ErrMissingParameter 발생",
				request: &Request{
					RefreshToken: "",
				},
			},
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrMissingParameter,
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "클라이언트 불일치시 ErrInvalidClient 발생",
				client: newClient("wrong client id", client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
				},
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidClient,
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "만료된 리프레시 토큰시 ErrExpiredResource 발생",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
				},
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				// 만료처리
				refreshToken.Range = period.New(time.Duration(-1))
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrExpiredResource,
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "스코프 미지정시 기존 토큰의 모든 스코프가 설정됨",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
				},
				accessTokenGenerator: generateTestAccessToken,
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				expiredToken.ApplyResourceOwnerInfo(testUsername, []string{"scope_1", "scope_2", "scope_3", "scope_4"})
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			refreshTokenGenerator: generateTestRefreshToken,
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.Equal(t, []string{"scope_1", "scope_2", "scope_3", "scope_4"}, accessToken.Scopes())
				},
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "기존 토큰 범위 외 스코프 요청시 ErrInvalidScope 발생",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
					Scope:        "scope_1 scope_2 wrong_scope",
				},
				accessTokenGenerator: generateTestAccessToken,
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				expiredToken.ApplyResourceOwnerInfo(testUsername, testScopeArray)
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			grantExceptCase: grantExceptCase{
				err: oautherr.ErrInvalidScope,
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "새 토큰에 기존 토큰의 정보가 올바르게 설정됨",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
					Scope:        scope.Join(testScopeArray),
				},
				accessTokenGenerator: generateTestAccessToken,
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				expiredToken.ApplyResourceOwnerInfo(testUsername, testScopeArray)
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			grantExceptCase: grantExceptCase{
				assertAccessToken: func(t *testing.T, accessToken *AccessToken) {
					assert.Equal(t, testClientID, accessToken.Client().Id())
					assert.Equal(t, testUsername, accessToken.Username())
				},
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "rotaiton이 fasle로 설정되어 있을 경우 기존의 리플래시 토큰을 사용한다.",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
					Scope:        scope.Join(testScopeArray),
				},
				accessTokenGenerator: generateTestAccessToken,
			},
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				expiredToken.ApplyResourceOwnerInfo(testUsername, testScopeArray)
				refreshToken := NewRefreshTokenWithRange(expiredToken, generateStoredRefreshToken, period.NewWithStartEnd(testStoredStart, testStoredEnd))
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			grantExceptCase: grantExceptCase{
				assertRefreshToken: func(t *testing.T, refreshToken *RefreshToken) {
					assert.Equal(t, testStoredRefreshTokenValue, refreshToken.Value())
					assert.Equal(t, testStoredStart, refreshToken.Range.Start())
					assert.Equal(t, testStoredEnd, refreshToken.Range.End())
				},
			},
		},
		{
			grantTestCase: grantTestCase{
				name:   "rotation이 true로 설정되어 있을 경우 새 리플레시 토큰을 발행한다.",
				client: newClient(testClientID, client.TypeConfidential, testScopeArray),
				request: &Request{
					RefreshToken: testRefreshTokenValue,
					Scope:        scope.Join(testScopeArray),
				},
				accessTokenGenerator: generateTestAccessToken,
			},
			refreshTokenGenerator: generateTestRefreshToken,
			refreshTokenRetriever: func() RetrieveRefreshToken {
				expiredToken := New(newClient(testClientID, client.TypeConfidential, testScopeArray), generateTestAccessToken)
				expiredToken.ApplyResourceOwnerInfo(testUsername, testScopeArray)
				refreshToken := NewRefreshToken(expiredToken, generateStoredRefreshToken)
				return retrieveRefreshToken(testRefreshTokenValue, refreshToken)
			}(),
			rotation: true,
			grantExceptCase: grantExceptCase{
				assertRefreshToken: func(t *testing.T, refreshToken *RefreshToken) {
					assert.Equal(t, testRefreshTokenValue, refreshToken.Value())
					assert.NotEqual(t, testStoredStart, refreshToken.Range.Start())
					assert.NotEqual(t, testStoredEnd, refreshToken.Range.End())
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granter := RefreshTokenGrant{
				accessTokenGenerator:  tc.accessTokenGenerator,
				refreshTokenGenerator: tc.refreshTokenGenerator,
				retrieveRefreshToken:  tc.refreshTokenRetriever,
				rotation:              tc.rotation,
			}

			accessToken, refreshToken, err := granter.GenerateToken(tc.client, tc.request)
			if tc.grantExceptCase.err != nil {
				assert.ErrorIs(t, err, tc.grantExceptCase.err)
			} else {
				assert.Nil(t, err)
				if tc.assertAccessToken != nil {
					tc.assertAccessToken(t, accessToken)
				}
				if tc.assertRefreshToken != nil {
					tc.assertRefreshToken(t, refreshToken)
				}
			}
		})
	}
}
