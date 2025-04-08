package service

import (
	"oauth-server-go/oauth/entity"
)

type ClientService struct {
	GetClient func(id string) (*entity.Client, error)
}

func NewClientService() *ClientService {
	return &ClientService{
		GetClient: getClient,
	}
}

func getClient(id string) (*entity.Client, error) {
	return clientRepository.FindByClientID(id)
}
