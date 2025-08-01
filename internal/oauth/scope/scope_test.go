package scope

import (
	"errors"
	oautherr "oauth-server-go/internal/oauth/errors"
	"slices"
	"testing"
)

func Test_Filter(t *testing.T) {
	scopes := []string{"scope_1", "scope_2"}

	tests := []struct {
		name     string
		codes    []string
		expected []string
		err      error
	}{
		{
			name:     "빈 배열로 요청",
			codes:    make([]string, 0),
			expected: scopes,
		},
		{
			name:  "요청한 스코프를 찾을 수 없음",
			codes: []string{"scope_3"},
			err:   oautherr.ErrInvalidScope,
		},
		{
			name:     "요창한 스코프를 반환",
			codes:    []string{"scope_1", "scope_2"},
			expected: []string{"scope_1", "scope_2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Filter(scopes, tc.codes)

			if !slices.Equal(s, tc.expected) {
				t.Errorf("반환되는 스코프는 %v이어야 합니다. (반환된 값: %v)", tc.expected, s)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("에러타입은 \"%v\"이어야 합니다. (반환된 에러: \"%v\")", tc.err, err)
			}
		})
	}
}
