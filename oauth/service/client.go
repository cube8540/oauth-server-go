package service

import (
	"oauth-server-go/oauth/entity"
)

type ClientService struct {
	GetClient func(id string) *entity.Client
}

func NewClientService() *ClientService {
	return &ClientService{
		GetClient: getClient,
	}
}

func getClient(id string) *entity.Client {
	return clientRepository.FindByClientID(id)
}
