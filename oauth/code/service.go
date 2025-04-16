package code

import (
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/pkg"
)

var codeGenerator AuthCodeGenerator

func init() {
	codeGenerator = UUIDAuthCodeGenerator
}

type Store interface {
	Save(c *AuthorizationCode) error
	Delete(c *AuthorizationCode) error
	FindByCode(code string) (*AuthorizationCode, error)
}

type Service struct {
	store Store
}

func NewService(r Store) *Service {
	return &Service{
		store: r,
	}
}

func (s *Service) New(c *client.Client, r *pkg.AuthorizationRequest) (*AuthorizationCode, error) {
	scopes, err := c.Scopes.GetAll(pkg.SplitScope(r.Scopes))
	if err != nil {
		return nil, err
	}
	authCode := NewAuthCode(codeGenerator)
	authCode.ClientID = c.ID
	authCode.Scopes = scopes
	if err = authCode.Set(r); err != nil {
		return nil, err
	}
	if err = s.store.Save(authCode); err != nil {
		return nil, err
	}
	return authCode, nil
}

func (s *Service) Retrieve(c string) (*AuthorizationCode, error) {
	authCode, err := s.store.FindByCode(c)
	if err != nil {
		return nil, err
	}
	scopes := authCode.Scopes
	if err = s.store.Delete(authCode); err != nil {
		return nil, err
	}
	authCode.Scopes = scopes
	return authCode, nil
}
