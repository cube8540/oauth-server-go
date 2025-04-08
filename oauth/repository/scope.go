package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type ScopeRepository struct {
	FindByCode func(c ...string) ([]entity.Scope, error)
}

func NewScopeRepository() *ScopeRepository {
	return &ScopeRepository{FindByCode: findByCode}
}

func findByCode(c ...string) ([]entity.Scope, error) {
	var scopes []entity.Scope
	err := conf.GetDB().Where("code in ?", c).Find(&scopes).Error
	if err != nil {
		return nil, err
	}
	return scopes, err
}
