package repository

import (
	"oauth-server-go/conf"
	"oauth-server-go/user/entity"
)

type AccountRepository struct {
	FindByUsername func(u string) (*entity.Account, error)
}

func NewAccountRepository() *AccountRepository {
	return &AccountRepository{
		FindByUsername: findAccountByUsername,
	}
}

func findAccountByUsername(u string) (*entity.Account, error) {
	var account entity.Account
	err := conf.GetDB().Where(&entity.Account{Username: u}).First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}
