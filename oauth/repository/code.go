package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type AuthCodeRepository struct {
	Save func(code *entity.AuthorizationCode) error
}

func NewAuthCodeRepository() *AuthCodeRepository {
	return &AuthCodeRepository{
		Save: save,
	}
}

func save(code *entity.AuthorizationCode) error {
	err := conf.GetDB().Create(code).Error
	return err
}
