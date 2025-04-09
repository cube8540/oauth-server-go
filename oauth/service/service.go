package service

import "oauth-server-go/oauth/repository"

var (
	clientRepository   *repository.ClientRepository
	authCodeRepository *repository.AuthCodeRepository
	scopeRepository    *repository.ScopeRepository
	tokenRepository    *repository.TokenRepository
)

func init() {
	clientRepository = repository.NewClientRepository()
	authCodeRepository = repository.NewAuthCodeRepository()
	scopeRepository = repository.NewScopeRepository()
	tokenRepository = repository.NewTokenRepository()
}
