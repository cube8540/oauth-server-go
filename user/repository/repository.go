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

func FindAccountByUsername(username string) *entity.Account {
	var account entity.Account
	err := db.Where(&entity.Account{Username: username}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else {
		return &account
	}
}
