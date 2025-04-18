package oauth

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/stretchr/testify/assert"
	"net/url"
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/pkg"
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
	query           url.Values
	clientRetriever func(id string) (*client.Client, error)
}

type handlerAuthorizeExpect struct {
	oauthError *Error
	routeError *routeErr

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
				oauthError: &Error{
					Code: pkg.ErrInvalidRequest,
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
				oauthError: &Error{
					Code: pkg.ErrInvalidRequest,
				},
				routeError: &routeErr{
					to: testutils.ParseURL(testLocalHost8080),
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
				oauthError: &Error{
					Code: pkg.ErrUnsupportedResponseType,
				},
				routeError: &routeErr{
					to: testutils.ParseURL(testLocalHost8080),
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
			if tc.expected.oauthError != nil {
				var oauthError *Error
				assert.ErrorAs(t, err, &oauthError)
				assert.Equal(t, tc.expected.oauthError.Code, oauthError.Code)
			}
			if tc.expected.routeError != nil {
				var routeError *routeErr
				assert.ErrorAs(t, err, &routeError)
				assert.Equal(t, tc.expected.routeError.to, routeError.to)
			}
			if tc.expected.oauthError == nil && tc.expected.routeError == nil {
				assert.Nil(t, err)
			}
			if tc.expected.savedRequestIntoSession != nil {
				serial := sessions.Default(c).Get(sessionKeyOriginAuthRequest)

				var savedAuthorizationRequest pkg.AuthorizationRequest
				_ = json.Unmarshal(serial.([]byte), &savedAuthorizationRequest)

				assert.Equal(t, *tc.expected.savedRequestIntoSession, savedAuthorizationRequest)
			}
		})
	}
}
