package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type AuthCodeRepository struct {
	Save       func(code *entity.AuthorizationCode) error
	FindByCode func(c string) (*entity.AuthorizationCode, error)
	Delete     func(code *entity.AuthorizationCode) error
}

func NewAuthCodeRepository() *AuthCodeRepository {
	return &AuthCodeRepository{
		Save:       saveCode,
		FindByCode: findCode,
		Delete:     deleteCode,
	}
}

func saveCode(code *entity.AuthorizationCode) error {
	return conf.GetDB().Create(code).Error
}

func findCode(c string) (*entity.AuthorizationCode, error) {
	var code entity.AuthorizationCode
	err := conf.GetDB().Preload("Scopes").Where(&entity.AuthorizationCode{Value: c}).First(&code).Error
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func deleteCode(c *entity.AuthorizationCode) error {
	err := conf.GetDB().Model(c).Association("Scopes").Delete(c.Scopes)
	if err != nil {
		return err
	}
	return conf.GetDB().Delete(c).Error
}
