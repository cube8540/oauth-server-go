package user

import (
	"errors"
	"gorm.io/gorm"
)

type AccountRepository interface {
	FindByUsername(username string) *Account
}

type GormAccountRepository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) AccountRepository {
	return &GormAccountRepository{db: db}
}

func (r GormAccountRepository) FindByUsername(username string) *Account {
	var account Account
	err := r.db.Where(&Account{Username: username}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else {
		return &account
	}
}
