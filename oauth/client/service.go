package client

import (
	"fmt"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/pkg/hash"
)

type Store interface {
	FindByClientID(id string) (*Client, error)
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{
		store: store,
	}
}

func (s *Service) GetClient(id string) (*Client, error) {
	return s.store.FindByClientID(id)
}

func (s *Service) Auth(id, secret string) (*Client, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: client id is required", ErrInvalidRequest)
	}
	c, err := s.store.FindByClientID(id)
	if err != nil {
		return nil, err
	}
	if c.Type == pkg.ClientTypePublic {
		return c, nil
	}
	eq, err := hash.Compare(c.Secret, secret)
	if err != nil {
		return nil, err
	}
	if !eq {
		return nil, fmt.Errorf("%w: secret is not matched", ErrAuthentication)
	}
	return c, nil
}
