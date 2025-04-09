package service

import (
	"oauth-server-go/crypto"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

var hasher crypto.Hasher

func init() {
	hasher = crypto.NewBcryptHasher()
}

type ClientService struct {
	GetClient func(id string) (*entity.Client, error)
	Auth      func(id, secret string) (*entity.Client, error)
}

func NewClientService() *ClientService {
	return &ClientService{
		GetClient: getClient,
		Auth:      auth,
	}
}

func getClient(id string) (*entity.Client, error) {
	return clientRepository.FindByClientID(id)
}

func auth(id, secret string) (*entity.Client, error) {
	c, err := clientRepository.FindByClientID(id)
	if err != nil {
		return nil, err
	}
	if c.Type == oauth.ClientTypePublic {
		return c, nil
	}
	eq, err := hasher.Compare(c.Secret, secret)
	if err != nil {
		return nil, err
	}
	if !eq {
		return nil, oauth.NewErr(oauth.ErrUnauthorizedClient, "secret is not matched")
	}
	return c, nil
}
