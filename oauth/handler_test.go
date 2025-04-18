package oauth

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/stretchr/testify/assert"
	"net/url"
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/security"
	"testing"
)

func fixedClientRetriever(id string, c *client.Client) func(id string) (*client.Client, error) {
	return func(i string) (*client.Client, error) {
		if id == id {
			return c, nil
		}
		return nil, client.ErrNotFound
	}
}

type requestTestCase struct {
	name            string
	query, form     url.Values
	clientRetriever func(id string) (*client.Client, error)
	requestConsumer func(c *client.Client, r *pkg.AuthorizationRequest) (any, error)
}

type errorExpected struct {
	oauthError *Error
	routeError *routeErr
}

type handlerAuthorizeExpect struct {
	errorExpected
	savedRequestIntoSession *pkg.AuthorizationRequest
}

type handlerAuthorizeTestCase struct {
	requestTestCase
	session  sessions.Session
	expected handlerAuthorizeExpect
}

func TestHandler_authorize(t *testing.T) {
	tests := []handlerAuthorizeTestCase{
		{
			requestTestCase: requestTestCase{
				name: "client_id가 입력 되지 않은 경우 ErrInvalidRequest 발생",
				query: map[string][]string{
					"client_id": nil,
				},
			},
			expected: handlerAuthorizeExpect{
				errorExpected: errorExpected{
					oauthError: &Error{
						Code: pkg.ErrInvalidRequest,
					},
				},
			},
		},
		{
			requestTestCase: requestTestCase{
				name: "response_type이 입력 되지 않은 경우 ErrInvalidRequest 발생",
				query: map[string][]string{
					"client_id":     {testClientIDValue},
					"response_type": nil,
					"redirect_uri":  {testLocalHost8080},
				},
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
			},
			expected: handlerAuthorizeExpect{
				errorExpected: errorExpected{
					oauthError: &Error{
						Code: pkg.ErrInvalidRequest,
					},
					routeError: &routeErr{
						to: testutils.ParseURL(testLocalHost8080),
					},
				},
			},
		},
		{
			requestTestCase: requestTestCase{
				name: "response_type이 code, token이 아닌 경우 ErrUnsupportedResponseType 발생",
				query: map[string][]string{
					"client_id":     {testClientIDValue},
					"response_type": {"wrong_type"},
					"redirect_uri":  {testLocalHost8080},
				},
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
			},
			expected: handlerAuthorizeExpect{
				errorExpected: errorExpected{
					oauthError: &Error{
						Code: pkg.ErrUnsupportedResponseType,
					},
					routeError: &routeErr{
						to: testutils.ParseURL(testLocalHost8080),
					},
				},
			},
		},
		{
			requestTestCase: requestTestCase{
				name: "세션에 요청 정보를 저장",
				query: map[string][]string{
					"client_id":     {testClientIDValue},
					"response_type": {string(pkg.ResponseTypeCode)},
					"redirect_uri":  {testLocalHost8080},
					"scope":         {"scope_1 scope_2"},
				},
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
			},
			session: testutils.NewSessions(testSessionID),
			expected: handlerAuthorizeExpect{
				savedRequestIntoSession: &pkg.AuthorizationRequest{
					ClientID:     testClientIDValue,
					ResponseType: pkg.ResponseTypeCode,
					Redirect:     testLocalHost8080,
					Scopes:       "scope_1 scope_2",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := h{
				clientRetriever: tc.clientRetriever,
			}
			c, _, engine := testutils.MockGin(tc.query, nil)

			engine.HTMLRender = testutils.NewHTMLRender()
			if tc.session != nil {
				c.Set(sessions.DefaultKey, tc.session)
			}

			err := handler.authorize(c)
			assertOAuthError(t, tc.expected.errorExpected, err)
			if tc.expected.savedRequestIntoSession != nil {
				serial := sessions.Default(c).Get(sessionKeyOriginAuthRequest)

				var savedAuthorizationRequest pkg.AuthorizationRequest
				_ = json.Unmarshal(serial.([]byte), &savedAuthorizationRequest)

				assert.Equal(t, *tc.expected.savedRequestIntoSession, savedAuthorizationRequest)
			}
		})
	}
}

type handlerApprovalExpect struct {
	errorExpected
	consumedClient      *client.Client
	consumedRequest     *pkg.AuthorizationRequest
	checkSessionDeleted bool
	deletedSession      bool
}

type handlerApprovalTestCase struct {
	requestTestCase
	setupSession  func() sessions.Session
	setupSecurity func() security.Store
	expected      handlerApprovalExpect
}

func TestHandler_approval(t *testing.T) {
	tests := []handlerApprovalTestCase{
		{
			requestTestCase: requestTestCase{
				name: "세션에 저장된 AuthorizationRequest가 없을 경우 ErrInvalidRequest 발생",
			},
			setupSession: func() sessions.Session {
				session := testutils.NewSessions(testSessionID)
				session.Delete(sessionKeyOriginAuthRequest)
				return session
			},
			expected: handlerApprovalExpect{
				errorExpected: errorExpected{
					oauthError: &Error{
						Code: pkg.ErrInvalidRequest,
					},
				},
			},
		},
		{
			requestTestCase: requestTestCase{
				name:            "승인된 스코프의 개수가 0개일 경우 ErrInvalidScope 발생",
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
				form: map[string][]string{
					"scope": {},
				},
			},
			setupSession: func() sessions.Session {
				origin := &pkg.AuthorizationRequest{
					ClientID:     testClientIDValue,
					ResponseType: pkg.ResponseTypeCode,
					Redirect:     testLocalHost8080,
					Scopes:       "scope_1 scope_2 scope_3",
				}
				session := testutils.NewSessions(testSessionID)
				serial, _ := json.Marshal(origin)
				session.Set(sessionKeyOriginAuthRequest, serial)
				return session
			},
			setupSecurity: func() security.Store {
				store := security.NewTestStore()
				_ = store.Set(&security.Login{Username: testUsername})
				return store
			},
			expected: handlerApprovalExpect{
				errorExpected: errorExpected{
					oauthError: &Error{
						Code: pkg.ErrInvalidScope,
					},
					routeError: &routeErr{
						to: testutils.ParseURL(testLocalHost8080),
					},
				},
			},
		},
		{
			requestTestCase: requestTestCase{
				name:            "로그인된 사용자와 승인된 스코프로 토큰 발행을 해야함",
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
				requestConsumer: func(c *client.Client, r *pkg.AuthorizationRequest) (any, error) {
					return nil, nil
				},
				form: map[string][]string{
					"scope": {"scope_1", "scope_2"},
				},
			},
			setupSession: func() sessions.Session {
				origin := &pkg.AuthorizationRequest{
					ClientID:     testClientIDValue,
					ResponseType: pkg.ResponseTypeCode,
					Redirect:     testLocalHost8080,
					Scopes:       "scope_1 scope_2 scope_3",
				}
				session := testutils.NewSessions(testSessionID)
				serial, _ := json.Marshal(origin)
				session.Set(sessionKeyOriginAuthRequest, serial)
				return session
			},
			setupSecurity: func() security.Store {
				store := security.NewTestStore()
				_ = store.Set(&security.Login{Username: testUsername})
				return store
			},
			expected: handlerApprovalExpect{
				consumedRequest: &pkg.AuthorizationRequest{
					ClientID:     testClientIDValue,
					ResponseType: pkg.ResponseTypeCode,
					Redirect:     testLocalHost8080,
					Scopes:       "scope_1 scope_2",
					Username:     testUsername,
				},
				consumedClient: testClient,
			},
		},
		{
			requestTestCase: requestTestCase{
				name:            "요청 종료 시 세션에 저장된 요청 정보를 삭제 한다",
				clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
				requestConsumer: func(c *client.Client, r *pkg.AuthorizationRequest) (any, error) {
					return nil, nil
				},
				form: map[string][]string{
					"scope": {"scope_1", "scope_2"},
				},
			},
			setupSession: func() sessions.Session {
				origin := &pkg.AuthorizationRequest{
					ClientID:     testClientIDValue,
					ResponseType: pkg.ResponseTypeCode,
					Redirect:     testLocalHost8080,
					Scopes:       "scope_1 scope_2 scope_3",
				}
				session := testutils.NewSessions(testSessionID)
				serial, _ := json.Marshal(origin)
				session.Set(sessionKeyOriginAuthRequest, serial)
				return session
			},
			setupSecurity: func() security.Store {
				store := security.NewTestStore()
				_ = store.Set(&security.Login{Username: testUsername})
				return store
			},
			expected: handlerApprovalExpect{
				checkSessionDeleted: true,
				deletedSession:      true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var consumedClient *client.Client
			var consumedRequest *pkg.AuthorizationRequest
			handler := h{
				clientRetriever: tc.clientRetriever,
				requestConsumer: func(c *client.Client, request *pkg.AuthorizationRequest) (any, error) {
					consumedClient = c
					consumedRequest = request
					return tc.requestConsumer(c, request)
				},
			}

			c, _, _ := testutils.MockGin(tc.query, tc.form)
			if tc.setupSession != nil {
				s := tc.setupSession()
				c.Set(sessions.DefaultKey, s)
			}
			if tc.setupSecurity != nil {
				s := tc.setupSecurity()
				c.Set(security.StoreKey, s)
			}

			err := handler.approval(c)
			assertOAuthError(t, tc.expected.errorExpected, err)
			if tc.expected.consumedClient != nil {
				assert.Equal(t, tc.expected.consumedClient, consumedClient)
			}
			if tc.expected.consumedRequest != nil {
				assert.Equal(t, tc.expected.consumedRequest, consumedRequest)
			}
			if tc.expected.checkSessionDeleted {
				if tc.expected.deletedSession {
					assert.Nil(t, sessions.Default(c).Get(sessionKeyOriginAuthRequest))
				} else {
					assert.NotNil(t, sessions.Default(c).Get(sessionKeyOriginAuthRequest))
				}
			}
		})
	}
}

func assertOAuthError(t *testing.T, expected errorExpected, err error) {
	if expected.oauthError != nil {
		var oauthError *Error
		assert.ErrorAs(t, err, &oauthError)
		assert.Equal(t, expected.oauthError.Code, oauthError.Code)
	}
	if expected.routeError != nil {
		var routeError *routeErr
		assert.ErrorAs(t, err, &routeError)
		assert.Equal(t, expected.routeError.to, routeError.to)
	}
	if expected.oauthError == nil && expected.routeError == nil {
		assert.Nil(t, err)
	}
}
