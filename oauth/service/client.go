package service

import (
	"oauth-server-go/crypto"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

type ClientRepository interface {
	FindByClientID(id string) (*entity.Client, error)
}

type ClientService struct {
	repository ClientRepository
	hasher     crypto.Hasher
}

func NewClientService(r ClientRepository, h crypto.Hasher) *ClientService {
	return &ClientService{
		repository: r,
		hasher:     h,
	}
}

func (s ClientService) GetClient(id string) (*entity.Client, error) {
	return s.repository.FindByClientID(id)
}

func (s ClientService) Auth(id, secret string) (*entity.Client, error) {
	c, err := s.repository.FindByClientID(id)
	if err != nil {
		return nil, err
	}
	if c.Type == oauth.ClientTypePublic {
		return c, nil
	}
	eq, err := s.hasher.Compare(c.Secret, secret)
	if err != nil {
		return nil, err
	}
	if !eq {
		return nil, oauth.NewErr(oauth.ErrUnauthorizedClient, "secret is not matched")
	}
	return c, nil
}
