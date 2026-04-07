package client

import (
	"github.com/stretchr/testify/assert"
	oautherr "oauth-server-go/internal/oauth/errors"
	"testing"
)

// 테스트용으로 사용할 상수 모음
const (
	testClientID = "test_client_id"
	testSecret   = "test_secret"
	testName     = "test_client_name"
)

// compareEqual 테스트로 사용할 패스워드 비교 함수
// 단순히 두 값이 서로 같은지만 확인한다.
func compareEqual(source, input string) (bool, error) {
	return source == input, nil
}

func TestAuthenticationProvider_Authenticate(t *testing.T) {

	provider := AuthenticationProvider{
		compare: compareEqual,
	}

	t.Run("클라이언트 아이디 누락시 ErrMissingParameter", func(t *testing.T) {
		_, err := provider.Authenticate("", "")

		assert.ErrorIs(t, err, oautherr.ErrMissingParameter)
	})

	t.Run("공개 클라이언트의 경우 패스워드를 확인 하지 않음", func(t *testing.T) {
		originClient := New(testClientID, testSecret, testName, TypePublic)

		provider.retriever = func(id string) (*Client, bool) {
			return originClient, true
		}

		c, _ := provider.Authenticate(testClientID, "wrong password")
		assert.Equal(t, originClient, c)
	})

	t.Run("기밀 클라이언트의 경우 패스워드 누락시 ErrMissingParameter", func(t *testing.T) {
		originClient := New(testClientID, testSecret, testName, TypeConfidential)

		provider.retriever = func(id string) (*Client, bool) {
			return originClient, true
		}

		_, err := provider.Authenticate(testClientID, "")
		assert.ErrorIs(t, err, oautherr.ErrMissingParameter)
	})

	t.Run("기밀 클라이언트의 경우 패스워드 일치 여부를 확인", func(t *testing.T) {
		originClient := New(testClientID, testSecret, testName, TypeConfidential)

		provider.retriever = func(id string) (*Client, bool) {
			return originClient, true
		}

		_, err := provider.Authenticate(testClientID, "wrong password")
		assert.ErrorIs(t, err, oautherr.ErrInvalidClient)
	})
}
