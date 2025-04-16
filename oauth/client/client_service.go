package client

import (
	"fmt"
	"oauth-server-go/crypto"
	"oauth-server-go/oauth/pkg"
)

type Store interface {
	FindByClientID(id string) (*Client, error)
}

type Service struct {
	store  Store
	hasher crypto.Hasher
}

func NewService(r Store, h crypto.Hasher) *Service {
	return &Service{
		store:  r,
		hasher: h,
	}
}

func (s *Service) GetClient(id string) (*Client, error) {
	c, err := s.store.FindByClientID(id)
	if err != nil {
		return nil, err
	}
	return c, nil
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
	eq, err := s.hasher.Compare(c.Secret, secret)
	if err != nil {
		return nil, err
	}
	if !eq {
		return nil, fmt.Errorf("%w: secret is not matched", ErrAuthentication)
	}
	return c, nil
}
