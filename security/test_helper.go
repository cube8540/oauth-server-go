package security

type TestStore struct {
	login *Login
}

func NewTestStore() *TestStore {
	return &TestStore{}
}

func (t *TestStore) Set(v *Login) error {
	t.login = v
	return nil
}

func (t *TestStore) Get() (*Login, bool) {
	return t.login, t.login != nil
}
