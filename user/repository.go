package user

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/conf"
)

type Repository interface {
	FindAccountByUsername(username string) *Account
}

type DefaultRepository struct {
	db *gorm.DB
}

func NewDefaultRepository() *DefaultRepository {
	return &DefaultRepository{conf.GetDB()}
}

func (r DefaultRepository) FindAccountByUsername(username string) *Account {
	var account Account
	err := r.db.Where(&Account{Username: username}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else {
		return &account
	}
}
