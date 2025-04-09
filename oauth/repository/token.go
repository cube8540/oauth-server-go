package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type TokenRepository struct {
	Save func(t *entity.Token) error
}

func NewTokenRepository() *TokenRepository {
	return &TokenRepository{
		Save: saveToken,
	}
}

func saveToken(t *entity.Token) error {
	return conf.GetDB().Save(t).Error
}
