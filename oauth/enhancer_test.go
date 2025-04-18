package oauth

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"oauth-server-go/internal/testutils"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"strconv"
	"testing"
)

const ()

type enhancerExpect struct {
	query url.Values
	err   error
}

type enhancerTestCase struct {
	name     string
	request  *pkg.AuthorizationRequest
	src      any
	url      *url.URL
	expected enhancerExpect
}

func TestFlow_authorizationCodeFlow(t *testing.T) {
	tests := []enhancerTestCase{
		{
			name: "response_type이 code가 아닌 경우 URL은 변경점이 없어야 한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeToken,
			},
			url: testutils.ParseURL(testLocalHost8080),
			expected: enhancerExpect{
				query: nil,
			},
		},
		{
			name: "src가 인가 코드가 아닌 경우 URL의 변경점이 없어야 한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeCode,
			},
			src: "wrong src",
			url: testutils.ParseURL(testLocalHost8080),
			expected: enhancerExpect{
				query: nil,
			},
		},
		{
			name: "인가 코드를 쿼리 파라미터로 붙여야 한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeCode,
			},
			src: &code.AuthorizationCode{
				Value: testAuthorizationCode,
				State: testAuthorizationState,
			},
			url: testutils.ParseURL(testLocalHost8080),
			expected: enhancerExpect{
				query: map[string][]string{
					"code":  {testAuthorizationCode},
					"state": {testAuthorizationState},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizationCodeFlow(tc.request, tc.src, tc.url)
			if tc.expected.err != nil {
				assert.ErrorIs(t, err, tc.expected.err)
			} else {
				assert.Nil(t, err)
			}
			if tc.expected.query != nil {
				assert.Equal(t, tc.url.Query(), tc.expected.query)
			}
		})
	}
}

func TestFlow_implicitFlow(t *testing.T) {
	tests := []enhancerTestCase{
		{
			name: "response_type이 token이 아닌 경우 URL의 변경점은 없어야 한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeCode,
			},
			expected: enhancerExpect{
				query: nil,
			},
		},
		{
			name: "src가 토큰이 아닌 경우 URL의 변경점은 없아야 한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeToken,
			},
			src: "wrong type",
			expected: enhancerExpect{
				query: nil,
			},
		},
		{
			name: "토큰 정보를 플레그먼트로 URL에 추가한다.",
			request: &pkg.AuthorizationRequest{
				ResponseType: pkg.ResponseTypeToken,
				State:        testAuthorizationState,
			},
			src: &TestToken{
				value:     testTokenValue,
				expiresIn: testExpiresIn,
				scope:     testScope,
			},
			url: testutils.ParseURL(testLocalHost8080),
			expected: enhancerExpect{
				query: map[string][]string{
					"access_token": {testTokenValue},
					"token_type":   {string(pkg.TokenTypeBearer)},
					"expires_in":   {strconv.FormatUint(testExpiresIn, 10)},
					"scope":        {testScope},
					"state":        {testAuthorizationState},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := implicitFlow(tc.request, tc.src, tc.url)
			if tc.expected.err != nil {
				assert.ErrorIs(t, err, tc.expected.err)
			} else {
				assert.Nil(t, err)
			}
			if tc.expected.query != nil {
				assert.Equal(t, tc.url.Fragment, tc.expected.query.Encode())
			}
		})
	}
}
