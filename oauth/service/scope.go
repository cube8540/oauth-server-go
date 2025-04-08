package service

import "oauth-server-go/oauth/entity"

type ScopeService struct {
	GetScopes func(code ...string) ([]entity.Scope, error)
}

func NewScopeService() *ScopeService {
	return &ScopeService{GetScopes: getScopes}
}

func getScopes(code ...string) ([]entity.Scope, error) {
	return scopeRepository.FindByCode(code...)
}
