package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/oauth/entity"
)

type ClientRepository struct {
	FindByClientID func(id string) (*entity.Client, error)
}

func NewClientRepository() *ClientRepository {
	return &ClientRepository{
		FindByClientID: findByClientID,
	}
}

func findByClientID(id string) (*entity.Client, error) {
	var client entity.Client
	err := conf.GetDB().Preload("Scopes").Where(&entity.Client{ClientID: id}).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}
