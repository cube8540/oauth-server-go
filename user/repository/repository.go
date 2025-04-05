package repository

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/conf"
	"oauth-server-go/user/entity"
)

var db *gorm.DB

func init() {
	db = conf.GetDB()
}

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
	err := db.Where(&entity.Account{Username: u}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else {
		return &account
	}
}
