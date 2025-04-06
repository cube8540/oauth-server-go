package service

import "oauth-server-go/oauth/repository"

var (
	clientRepository   *repository.ClientRepository
	authCodeRepository *repository.AuthCodeRepository
)

func init() {
	clientRepository = repository.NewClientRepository()
	authCodeRepository = repository.NewAuthCodeRepository()
}
