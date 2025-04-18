package token

type TestToken struct {
	Value     string
	ExpiresIn uint
	Scope     string
	Username  string
	ClientID  string
	IssuedAt  uint
}

func (t *TestToken) GetValue() string {
	return t.Value
}

func (t *TestToken) IsActive() bool {
	return true
}

func (t *TestToken) GetClientID() string {
	return t.ClientID
}

func (t *TestToken) GetUsername() string {
	return t.Username
}

func (t *TestToken) GetScopes() string {
	return t.Scope
}

func (t *TestToken) GetIssuedAt() uint {
	return t.IssuedAt
}

func (t *TestToken) GetExpiredAt() uint {
	return t.ExpiresIn
}
