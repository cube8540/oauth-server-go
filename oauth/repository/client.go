package repository

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type ClientRepository struct {
	FindByClientID func(id string) *entity.Client
}

func NewClientRepository() *ClientRepository {
	return &ClientRepository{
		FindByClientID: findByClientID,
	}
}

func findByClientID(id string) *entity.Client {
	var client entity.Client
	err := conf.GetDB().Where(&entity.Client{ClientID: id}).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return &client
}
