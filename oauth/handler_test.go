package oauth

import (
	"encoding/json"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/stretchr/testify/assert"
	"net/url"
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/pkg"
	"testing"
)

const (
	testSessionID = "test_sessions"

	testClientID      = 1
	testClientIDValue = "client_id"

	testLocalHost8080 = "http://localhost:8080"
	testLocalHost7070 = "http://localhost:7070"
)

var testScopes = []string{"scope_1", "scope_2", "scope_3"}

var testClient = &client.Client{
	ID:        testClientID,
	ClientID:  testClientIDValue,
	Redirects: []string{testLocalHost8080, testLocalHost7070},
	Scopes:    testutils.ScopeList(testScopes...),
}

func fixedClientRetriever(id string, c *client.Client) func(id string) (*client.Client, error) {
	return func(i string) (*client.Client, error) {
		if id == id {
			return c, nil
		}
		return nil, client.ErrNotFound
	}
}

func TestHandler_authorize(t *testing.T) {
	handler := h{
		clientRetriever: fixedClientRetriever(testClientIDValue, testClient),
	}
	t.Run("client_id가 입력되지 않았을 경우 ErrInvalidRequest 발생", func(t *testing.T) {
		query := url.Values{
			"client_id": nil,
		}

		c, _, _ := testutils.MockGin(query, nil)
		err := handler.authorize(c)

		var oauthErr *Error
		if errors.As(err, &oauthErr) {
			assert.Equal(t, oauthErr.Code, pkg.ErrInvalidRequest)
		} else {
			t.Errorf("oauth.Error이 발생해야 합니다. actual: %v", err)
		}
	})
	t.Run("response_type이 입력되지 않았을 경우 ErrInvalidRequest 발생", func(t *testing.T) {
		query := url.Values{
			"client_id":     []string{testClientIDValue},
			"response_type": nil,
			"redirect_uri":  []string{testLocalHost8080},
		}

		c, _, _ := testutils.MockGin(query, nil)
		err := handler.authorize(c)
		assertWrapError(t, err, pkg.ErrInvalidRequest, testutils.ParseURL(testLocalHost8080))
	})
	t.Run("response_type이 code, token이 아닌 경우 ErrUnsupportedResponseType 발생", func(t *testing.T) {
		query := url.Values{
			"client_id":     []string{testClientIDValue},
			"response_type": []string{"wrong_type"},
			"redirect_uri":  []string{testLocalHost8080},
		}

		c, _, _ := testutils.MockGin(query, nil)
		err := handler.authorize(c)
		assertWrapError(t, err, pkg.ErrUnsupportedResponseType, testutils.ParseURL(testLocalHost8080))
	})
	t.Run("세션에 요청 정보를 저장", func(t *testing.T) {
		query := url.Values{
			"client_id":     []string{testClientIDValue},
			"response_type": []string{string(pkg.ResponseTypeCode)},
			"redirect_uri":  []string{testLocalHost8080},
			"scope":         []string{"scope_1 scope_2"},
		}

		c, _, engine := testutils.MockGin(query, nil)
		engine.HTMLRender = testutils.NewHTMLRender()

		s := testutils.NewSessions(testSessionID)
		c.Set(sessions.DefaultKey, s)

		_ = handler.authorize(c)

		origin := &pkg.AuthorizationRequest{
			ClientID:     testClientIDValue,
			Redirect:     testLocalHost8080,
			Scopes:       "scope_1 scope_2",
			ResponseType: pkg.ResponseTypeCode,
		}
		expect, _ := json.Marshal(origin)
		saved := s.Get(sessionKeyOriginAuthRequest)
		assert.Equal(t, saved, expect)
	})
}

func assertWrapError(t *testing.T, err error, code string, to *url.URL) {
	var route *routeErr
	if errors.As(err, &route) {
		assert.Equal(t, route.to, to)

		var oauthErr *Error
		if errors.As(err, &oauthErr) {
			assert.Equal(t, oauthErr.Code, code)
		} else {
			t.Errorf("oauth.Error가 발생해야 합니다. actual: %v", err)
		}
	} else {
		t.Errorf("oauth.routeError가 발생해야 합니다. actual: %v", err)
	}
}
