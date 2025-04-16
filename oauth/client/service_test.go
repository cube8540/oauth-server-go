package client

import (
	"errors"
	"oauth-server-go/oauth/pkg"
	"testing"
)

type mockClientRepository struct {
	findByClientID func(id string) (*Client, error)
}

func (m *mockClientRepository) FindByClientID(id string) (*Client, error) {
	return m.findByClientID(id)
}

type mockHasher struct {
	hashing func(v string) (string, error)
	compare func(hashed, cmp string) (bool, error)
}

func (m *mockHasher) Hashing(v string) (string, error) {
	return m.hashing(v)
}

func (m *mockHasher) Compare(hashed, cmp string) (bool, error) {
	return m.compare(hashed, cmp)
}

func TestClientService_Auth(t *testing.T) {
	r := mockClientRepository{}
	h := mockHasher{}

	srv := NewService(&r, &h)
	t.Run("클라이언트 아이디 미입력", func(t *testing.T) {
		_, err := srv.Auth("", "secret")

		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("에러는 %v이어야 합니다.", ErrInvalidRequest)
		}
	})

	t.Run("클라이언트를 찾을 수 없음", func(t *testing.T) {
		r.findByClientID = func(id string) (*Client, error) {
			if id == "clientId" {
				return nil, ErrNotFound
			}
			return nil, errors.New("undefined error")
		}

		_, err := srv.Auth("clientId", "secret")
		if err == nil {
			t.Errorf("에러가 반드시 반환 되어야 합니다.")
		}
	})

	t.Run("공개 클라이언트인 경우", func(t *testing.T) {
		mockClient := &Client{Type: pkg.ClientTypePublic}
		r.findByClientID = func(id string) (*Client, error) {
			if id == "clientId" {
				return mockClient, nil
			}
			return nil, errors.New("undefined error")
		}
		h.compare = func(hashed, cmp string) (bool, error) {
			return false, nil
		}

		c, err := srv.Auth("clientId", "")
		if c != mockClient || err != nil {
			t.Errorf("모킹된 클라이언트가 반드시 반환 되어야 합니다.")
		}
	})

	t.Run("기밀 클라이언트인 경우", func(t *testing.T) {
		mockClient := &Client{
			Type:   pkg.ClientTypeConfidential,
			Secret: "Secret",
		}
		r.findByClientID = func(id string) (*Client, error) {
			if id == "clientId" {
				return mockClient, nil
			}
			return nil, errors.New("undefined error")
		}
		h.compare = func(hashed, cmp string) (bool, error) {
			return hashed == cmp, nil
		}

		t.Run("클라이언트 시크릿이 다를 경우", func(t *testing.T) {
			_, err := srv.Auth("clientId", "different secret")

			if !errors.Is(err, ErrAuthentication) {
				t.Errorf("에러 타입은 %v이어야 합니다.", ErrAuthentication)
			}
		})
	})
}
