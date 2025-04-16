package client

import (
	"errors"
	"slices"
	"testing"
)

func scope(c string) Scope {
	return Scope{
		Code: c,
	}
}

func TestGrantedScopes_GetAll(t *testing.T) {
	scopes := []Scope{
		scope("scope_1"), scope("scope_2"), scope("scope_2"),
	}
	grantedScopes := GrantedScopes(scopes)

	tests := []struct {
		name     string
		request  []string
		expected []Scope
		err      error
	}{
		{
			name:     "빈 배열로 요청",
			request:  make([]string, 0),
			expected: scopes,
		},
		{
			name:    "요청한 스코프를 찾을 수 없음",
			request: []string{"scope_3"},
			err:     ErrInvalidScope,
		},
		{
			name:     "요창한 스코프를 반환",
			request:  []string{"scope_1", "scope_2"},
			expected: []Scope{scope("scope_1"), scope("scope_2")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := grantedScopes.GetAll(tc.request)

			if !slices.Equal(s, tc.expected) {
				t.Errorf("반환되는 스코프는 %v이어야 합니다. (반환된 값: %v)", tc.expected, s)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("에러타입은 \"%v\"이어야 합니다. (반환된 에러: \"%v\")", tc.err, err)
			}
		})
	}
}

func TestClient_RedirectURL(t *testing.T) {
	client := Client{}
	tests := []struct {
		name       string
		storedUrl  []string
		requestUrl string
		expected   string
		err        error
	}{
		{
			name:       "단건/리다이렉트 URL이 입력 되지 않음",
			storedUrl:  []string{"store.com"},
			requestUrl: "store.com",
			expected:   "store.com",
		},
		{
			name:       "단건/리다이렉트 URL이 불일치",
			storedUrl:  []string{"store.com"},
			requestUrl: "something.com",
			err:        ErrInvalidRedirectURI,
		},
		{
			name:       "단건/리다이렉트 URL이 일치",
			storedUrl:  []string{"store.com"},
			requestUrl: "store.com",
			expected:   "store.com",
		},
		{
			name:       "다건/리다이렉트 URL이 입력 되지 않음",
			storedUrl:  []string{"store1.com", "store2.com"},
			requestUrl: "",
			err:        ErrInvalidRedirectURI,
		},
		{
			name:       "다건/리다이렉트 URL을 찾을 수 없음",
			storedUrl:  []string{"store1.com", "store2.com"},
			requestUrl: "something.com",
			err:        ErrInvalidRedirectURI,
		},
		{
			name:       "다건/라디아렉트 URL을 찾음",
			storedUrl:  []string{"store1.com", "store2.com"},
			requestUrl: "store1.com",
			expected:   "store1.com",
		},
	}

	for _, tc := range tests {
		client.Redirects = tc.storedUrl
		t.Run(tc.name, func(t *testing.T) {
			r, err := client.RedirectURL(tc.requestUrl)

			if r != tc.expected {
				t.Errorf("반환되는 리다이렉트 URL은 \"%s\" 이어야 합니다. (반횐된 값: %s)", tc.expected, r)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("반환되는 에러는 \"%v\" 이어야 합니다. (반환된 에러: %v)", tc.err, err)
			}
		})
	}
}
