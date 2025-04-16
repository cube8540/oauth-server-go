package code

import (
	"testing"
)

type mockStore struct {
	save       func(c *AuthorizationCode) error
	delete     func(c *AuthorizationCode) error
	findByCode func(code string) (*AuthorizationCode, error)
}

func (m *mockStore) Save(c *AuthorizationCode) error {
	return m.save(c)
}

func (m *mockStore) Delete(c *AuthorizationCode) error {
	return m.delete(c)
}

func (m *mockStore) FindByCode(code string) (*AuthorizationCode, error) {
	return m.findByCode(code)
}

func TestService_Retrieve(t *testing.T) {
	store := mockStore{}
	srv := NewService(&store)

	code := AuthorizationCode{}

	var deletedAuthCode *AuthorizationCode
	store.findByCode = func(c string) (*AuthorizationCode, error) {
		if c == "code" {
			return &code, nil
		}
		return nil, ErrNotFound
	}
	store.delete = func(c *AuthorizationCode) error {
		deletedAuthCode = c
		return nil
	}

	res, _ := srv.Retrieve("code")
	if res != &code {
		t.Errorf("저장소에서 검색된 인가 코드를 반환해야 합니다.\n예상: %+v\n실제: %+v", &code, res)
	}
	if deletedAuthCode != &code {
		t.Errorf("검색된 인가 코드는 삭제되어야 합니다.")
	}
}
