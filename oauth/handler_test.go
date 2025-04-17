package oauth

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/url"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/oauth/token"
	"oauth-server-go/testutils"
	"testing"
)

const (
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

type handlerTestCase struct {
	name            string
	query           url.Values
	clientRetriever func(id string) (*client.Client, error)
	requestConsumer func(c *client.Client, request *pkg.AuthorizationRequest) (any, error)
	tokenIssuer     func(c *client.Client, r *pkg.TokenRequest) (*token.Token, *token.RefreshToken, error)
	introspector    func(c *client.Client, r *pkg.IntrospectionRequest) (*pkg.Introspection, error)
	expect          expect
}

type expect struct {
	oauthErr *Error
	err      error
}

func urlParse(u string) *url.URL {
	r, _ := url.Parse(u)
	return r
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

		c, _ := testutils.MockGin(query, nil)
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

		c, _ := testutils.MockGin(query, nil)
		err := handler.authorize(c)
		assertWrapError(t, err, pkg.ErrInvalidRequest, urlParse(testLocalHost8080))
	})
	t.Run("response_type이 code, token이 아닌 경우 ErrUnsupportedResponseType 발생", func(t *testing.T) {
		query := url.Values{
			"client_id":     []string{testClientIDValue},
			"response_type": []string{"wrong_type"},
			"redirect_uri":  []string{testLocalHost8080},
		}

		c, _ := testutils.MockGin(query, nil)
		err := handler.authorize(c)
		assertWrapError(t, err, pkg.ErrUnsupportedResponseType, urlParse(testLocalHost8080))
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
