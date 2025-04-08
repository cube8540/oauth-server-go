package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type ScopeRepository struct {
	FindByCode func(c ...string) []entity.Scope
}

func NewScopeRepository() *ScopeRepository {
	return &ScopeRepository{FindByCode: findByCode}
}

func findByCode(c ...string) []entity.Scope {
	var scopes []entity.Scope
	conf.GetDB().Where("code in ?", c).Find(&scopes)
	return scopes
}
