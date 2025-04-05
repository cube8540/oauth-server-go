package repository

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/conf"
	"oauth-server-go/user/entity"
)

type AccountRepository struct {
	FindByUsername func(u string) *entity.Account
}

func NewAccountRepository() *AccountRepository {
	return &AccountRepository{
		FindByUsername: findAccountByUsername,
	}
}

func findAccountByUsername(u string) *entity.Account {
	var account entity.Account
	err := conf.GetDB().Where(&entity.Account{Username: u}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else {
		return &account
	}
}
